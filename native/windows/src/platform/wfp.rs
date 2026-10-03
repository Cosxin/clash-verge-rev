// SPDX-License-Identifier: GPL-3.0-only
use super::{wide, win_error};
use crate::model::AppBanPolicy;
use std::{
    ptr::{null, null_mut},
    slice,
};
use windows_sys::{
    Win32::{
        Foundation::{FWP_E_ALREADY_EXISTS, FWP_E_PROVIDER_CONTEXT_NOT_FOUND, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::*,
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
    core::GUID,
};

const PROVIDER: GUID = GUID::from_u128(0x2355d5ea_5d40_4f43_90ae_23468d941c65);
const SUBLAYER: GUID = GUID::from_u128(0x6d859f1f_8a6d_4935_b42c_6066e4197d88);
const METADATA: GUID = GUID::from_u128(0xec2c9633_20f5_425e_bf0a_38f0da883578);
const LAYERS: [GUID; 4] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];

fn same_guid(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1 && left.data2 == right.data2 && left.data3 == right.data3 && left.data4 == right.data4
}

pub struct Engine(HANDLE);

struct WfpMemory<T>(*mut T);
impl<T> Drop for WfpMemory<T> {
    fn drop(&mut self) {
        unsafe {
            FwpmFreeMemory0((&mut self.0 as *mut *mut T).cast());
        }
    }
}
fn check(code: u32, operation: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(win_error(operation, code))
    }
}

impl Engine {
    pub fn open() -> Result<Self, String> {
        let mut handle = null_mut();
        check(
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), null(), &mut handle) },
            "Open WFP engine",
        )?;
        Ok(Self(handle))
    }

    pub fn policy(&self) -> Result<Option<AppBanPolicy>, String> {
        let mut filter = WfpMemory(null_mut());
        let result = unsafe { FwpmProviderContextGetByKey0(self.0, &METADATA, &mut filter.0) };
        if result == FWP_E_PROVIDER_CONTEXT_NOT_FOUND as u32 {
            return Ok(None);
        }
        check(result, "Read installed WFP generation")?;
        let filter = unsafe { &*filter.0 };
        if filter.providerKey.is_null()
            || !same_guid(unsafe { &*filter.providerKey }, &PROVIDER)
            || filter.providerData.size as usize > crate::model::MAX_MESSAGE
        {
            return Err("Installed native policy marker has invalid ownership or length".into());
        }
        let bytes = if filter.providerData.size == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(filter.providerData.data, filter.providerData.size as usize) }
        };
        let policy: AppBanPolicy =
            serde_json::from_slice(bytes).map_err(|e| format!("Invalid installed WFP policy: {e}"))?;
        policy.validate(
            policy
                .generation
                .checked_sub(1)
                .ok_or("Invalid native generation zero")?,
        )?;
        if self.owned_keys()?.len() != policy.process_paths.len() * 4 {
            return Err("Installed native filters do not match their generation marker".into());
        }
        Ok(Some(policy))
    }

    fn owned_keys(&self) -> Result<Vec<GUID>, String> {
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &PROVIDER as *const GUID as *mut GUID,
            actionMask: u32::MAX,
            flags: FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
            ..unsafe { std::mem::zeroed() }
        };
        let mut enumeration = null_mut();
        check(
            unsafe { FwpmFilterCreateEnumHandle0(self.0, &template, &mut enumeration) },
            "Enumerate owned WFP filters",
        )?;
        let result = (|| {
            let mut keys = Vec::new();
            loop {
                let mut entries = WfpMemory(null_mut::<*mut FWPM_FILTER0>());
                let mut count = 0;
                check(
                    unsafe { FwpmFilterEnum0(self.0, enumeration, 256, &mut entries.0, &mut count) },
                    "Read owned WFP filters",
                )?;
                if count == 0 {
                    break;
                }
                for &entry in unsafe { slice::from_raw_parts(entries.0, count as usize) } {
                    let filter = unsafe { &*entry };
                    if !filter.providerKey.is_null() && same_guid(unsafe { &*filter.providerKey }, &PROVIDER) {
                        if filter.flags & FWPM_FILTER_FLAG_DISABLED != 0 {
                            return Err("Installed native filters are disabled; configure the owner service for automatic start".into());
                        }
                        if filter.flags & FWPM_FILTER_FLAG_PERSISTENT == 0
                            || filter.action.r#type != FWP_ACTION_BLOCK
                            || filter.numFilterConditions != 1
                            || filter.filterCondition.is_null()
                            || !same_guid(
                                unsafe { &(*filter.filterCondition).fieldKey },
                                &FWPM_CONDITION_ALE_APP_ID,
                            )
                            || !same_guid(&filter.subLayerKey, &SUBLAYER)
                            || !LAYERS.iter().any(|layer| same_guid(layer, &filter.layerKey))
                        {
                            return Err("Owned native filter is not an exact persistent ALE executable ban".into());
                        }
                        keys.push(filter.filterKey);
                    }
                }
                if keys.len() > crate::model::MAX_PATHS * 4 {
                    return Err("Owned WFP filter set exceeds native policy limits".into());
                }
            }
            Ok(keys)
        })();
        unsafe {
            FwpmFilterDestroyEnumHandle0(self.0, enumeration);
        }
        result
    }

    pub fn replace(&self, policy: &AppBanPolicy) -> Result<(), String> {
        let own_exe =
            std::fs::canonicalize(std::env::current_exe().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let mut apps = Vec::with_capacity(policy.process_paths.len());
        for path in &policy.process_paths {
            let resolved = std::fs::canonicalize(path).map_err(|e| format!("Executable path is unavailable: {e}"))?;
            if resolved == own_exe || !resolved.is_file() {
                return Err("Cannot ban the native policy owner or a non-file path".into());
            }
            let mut blob = WfpMemory(null_mut());
            check(
                unsafe { FwpmGetAppIdFromFileName0(wide(path)?.as_ptr(), &mut blob.0) },
                "Resolve WFP executable identity",
            )?;
            apps.push(blob);
        }
        let mut metadata = serde_json::to_vec(policy).map_err(|e| e.to_string())?;
        if metadata.len() > crate::model::MAX_MESSAGE {
            return Err("Native policy metadata exceeds byte limit".into());
        }
        check(
            unsafe { FwpmTransactionBegin0(self.0, 0) },
            "Begin WFP policy transaction",
        )?;
        let result = (|| {
            let installed_generation = self.policy()?.as_ref().map_or(0, |installed| installed.generation);
            if installed_generation.checked_add(1) != Some(policy.generation) {
                return Err("Native generation changed before WFP transaction; reload before saving".into());
            }
            let mut name = wide("Network Control executable bans")?;
            let mut service = wide(super::SERVICE_NAME)?;
            let display = FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            };
            let provider = FWPM_PROVIDER0 {
                providerKey: PROVIDER,
                displayData: display,
                flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                serviceName: service.as_mut_ptr(),
                ..unsafe { std::mem::zeroed() }
            };
            let code = unsafe { FwpmProviderAdd0(self.0, &provider, null_mut()) };
            if code != FWP_E_ALREADY_EXISTS as u32 {
                check(code, "Create native WFP provider")?;
            }
            let sublayer = FWPM_SUBLAYER0 {
                subLayerKey: SUBLAYER,
                displayData: display,
                flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                providerKey: &PROVIDER as *const GUID as *mut GUID,
                weight: 0xfff0,
                ..unsafe { std::mem::zeroed() }
            };
            let code = unsafe { FwpmSubLayerAdd0(self.0, &sublayer, null_mut()) };
            if code != FWP_E_ALREADY_EXISTS as u32 {
                check(code, "Create native WFP sublayer")?;
            }
            for key in self.owned_keys()? {
                check(
                    unsafe { FwpmFilterDeleteByKey0(self.0, &key) },
                    "Replace owned WFP filter",
                )?;
            }
            for app in &apps {
                let mut condition = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
                    },
                };
                for layer in LAYERS {
                    let filter = FWPM_FILTER0 {
                        displayData: display,
                        flags: FWPM_FILTER_FLAG_PERSISTENT,
                        providerKey: &PROVIDER as *const GUID as *mut GUID,
                        layerKey: layer,
                        subLayerKey: SUBLAYER,
                        action: FWPM_ACTION0 {
                            r#type: FWP_ACTION_BLOCK,
                            ..unsafe { std::mem::zeroed() }
                        },
                        numFilterConditions: 1,
                        filterCondition: &mut condition,
                        ..unsafe { std::mem::zeroed() }
                    };
                    check(
                        unsafe { FwpmFilterAdd0(self.0, &filter, null_mut(), null_mut()) },
                        "Install native executable ban",
                    )?;
                }
            }
            let code = unsafe { FwpmProviderContextDeleteByKey0(self.0, &METADATA) };
            if code != FWP_E_PROVIDER_CONTEXT_NOT_FOUND as u32 {
                check(code, "Replace native generation marker")?;
            }
            let mut data = FWP_BYTE_BLOB {
                size: metadata.len() as u32,
                data: metadata.as_mut_ptr(),
            };
            let marker = FWPM_PROVIDER_CONTEXT0 {
                providerContextKey: METADATA,
                displayData: display,
                flags: FWPM_PROVIDER_CONTEXT_FLAG_PERSISTENT,
                providerKey: &PROVIDER as *const GUID as *mut GUID,
                providerData: data,
                r#type: FWPM_GENERAL_CONTEXT,
                Anonymous: FWPM_PROVIDER_CONTEXT0_0 { dataBuffer: &mut data },
                ..unsafe { std::mem::zeroed() }
            };
            check(
                unsafe { FwpmProviderContextAdd0(self.0, &marker, null_mut(), null_mut()) },
                "Install native generation marker",
            )?;
            check(
                unsafe { FwpmTransactionCommit0(self.0) },
                "Commit WFP policy transaction",
            )
        })();
        if result.is_err() {
            unsafe {
                FwpmTransactionAbort0(self.0);
            }
        }
        result
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}
