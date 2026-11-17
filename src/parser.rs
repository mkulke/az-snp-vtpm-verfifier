use crate::types::{AttestationReport as HclAttestationReport, HCL_AKPUB_KEY_ID, VarData};
use jsonwebkey::JsonWebKey;
use std::fmt;
use zerocopy::FromBytes;

#[derive(Debug)]
pub enum ParserError {
    AttestationReport,
    VarData,
    AkPub,
}

impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParserError::AttestationReport => {
                write!(f, "Could not parse buffer into Attestation Report")
            }
            ParserError::VarData => {
                write!(f, "Could not parse buffer into Variable Data")
            }
            ParserError::AkPub => {
                write!(f, "Could not find Public Attestation Key in Variable Data")
            }
        }
    }
}

pub struct ReportParser {
    hcl_report: HclAttestationReport,
    ak_pub: JsonWebKey,
    var_data: Vec<u8>,
}

impl ReportParser {
    pub fn new(buffer: Vec<u8>) -> Result<Self, ParserError> {
        let (report, remaining) = HclAttestationReport::read_from_prefix(&buffer)
            .map_err(|_| ParserError::AttestationReport)?;
        let size = report.hcl_data.variable_data_size as usize;
        let remaining_slice = remaining.get(..size).ok_or(ParserError::VarData)?;
        let var_data: VarData =
            serde_json::from_slice(remaining_slice).map_err(|_| ParserError::VarData)?;
        let ak_pub = var_data
            .keys
            .into_iter()
            .find(|key| {
                let Some(ref key_id) = key.key_id else {
                    return false;
                };
                key_id == HCL_AKPUB_KEY_ID
            })
            .ok_or(ParserError::AkPub)?;
        Ok(Self {
            hcl_report: report,
            ak_pub,
            var_data: remaining_slice.into(),
        })
    }

    pub fn attestation_report(&self) -> &HclAttestationReport {
        &self.hcl_report
    }

    pub fn ak_pub(&self) -> &JsonWebKey {
        &self.ak_pub
    }

    pub fn var_data(&self) -> &[u8] {
        &self.var_data
    }
}
