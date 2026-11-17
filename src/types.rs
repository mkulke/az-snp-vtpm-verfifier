use jsonwebkey::JsonWebKey;
use serde::Deserialize;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const HCL_AKPUB_KEY_ID: &str = "HCLAkPub";
const TD_REPORT_SIZE: usize = size_of::<TdReport>();
pub const SNP_REPORT_SIZE: usize = 1184;
const fn max(a: usize, b: usize) -> usize {
    if a > b {
        return a;
    }
    b
}
const MAX_REPORT_SIZE: usize = max(SNP_REPORT_SIZE, TD_REPORT_SIZE);
pub const SNP_REPORT_TYPE: u32 = 2;

#[repr(C)]
#[derive(Clone, Debug, PartialEq, FromBytes, Immutable, IntoBytes)]
struct AttestationHeader {
    signature: u32,
    version: u32,
    report_size: u32,
    request_type: u32,
    status: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq, FromBytes, Immutable, IntoBytes)]
pub struct IgvmRequestData {
    data_size: u32,
    version: u32,
    pub report_type: u32,
    report_data_hash_type: u32,
    pub variable_data_size: u32,
    variable_data: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq, FromBytes, Immutable, IntoBytes)]
pub struct AttestationReport {
    header: AttestationHeader,
    pub hw_report: [u8; MAX_REPORT_SIZE],
    pub hcl_data: IgvmRequestData,
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, Copy, Clone, Debug, PartialEq)]
pub struct TdReport {
    pub report_mac: ReportMac,
    pub tee_tcb_info: [u8; 239],
    pub _reserved: [u8; 17],
    pub tdinfo: TdInfo,
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, Copy, Clone, Debug, PartialEq)]
pub struct ReportMac {
    pub reporttype: ReportType,
    pub _reserved_1: [u8; 12],
    pub cpusvn: [u8; 16],
    pub tee_tcb_info_hash: [u8; 48],
    pub tee_info_hash: [u8; 48],
    pub reportdata: [u8; 64],
    pub _reserved_2: [u8; 32],
    pub mac: [u8; 32],
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, Copy, Clone, Debug, PartialEq)]
pub struct Rtmr {
    pub register_data: [u8; 48],
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, Copy, Clone, Debug, PartialEq)]
pub struct TdInfo {
    pub attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mrtd: [u8; 48],
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    pub rtmr: [Rtmr; 4],
    pub _reserved: [u8; 112],
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, Copy, Clone, Debug, PartialEq)]
pub struct ReportType {
    pub r#type: u8,
    pub subtype: u8,
    pub version: u8,
    pub _reserved: u8,
}

#[derive(Deserialize, Debug)]
pub struct VarData {
    pub keys: Vec<JsonWebKey>,
}
