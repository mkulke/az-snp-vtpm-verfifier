use bitvec::{order::Lsb0, view::BitView};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey as PublicKey;
use openssl::sha::{Sha256, sha256};
use openssl::sign::Verifier as SignatureVerifier;
use serde::Deserialize;
use serde_with::{hex::Hex, serde_as};
use sev::firmware::guest::AttestationReport as SevSnpAttestationReport;
use sev::parser::ByteParser;
use std::collections::BTreeMap;
use tpm2_protocol::{
    TpmUnmarshal,
    data::{TpmAlgId, TpmsAttest, TpmuAttest},
};

mod parser;
mod types;

const QUOTE: &[u8] = include_bytes!("../test/tpm-quote-v1.json");
const HCL_REPORT: &[u8] = include_bytes!("../test/hcl-report.bin");
const NONCE: &[u8] = "challenge".as_bytes();

#[serde_as]
#[derive(Deserialize, Clone, Debug)]
pub(crate) struct TpmQuote {
    #[serde_as(as = "Hex")]
    pub(crate) signature: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub(crate) message: Vec<u8>,
    #[serde_as(as = "Vec<Hex>")]
    pub(crate) pcrs: Vec<Vec<u8>>,
}

fn main() {
    let quote: TpmQuote = serde_json::from_slice(QUOTE).unwrap();

    let parser = parser::ReportParser::new(HCL_REPORT.into()).unwrap();

    let attestation_report = parser.attestation_report();
    let der = parser.ak_pub().key.try_to_der().unwrap();
    let ak_pub = PublicKey::public_key_from_der(&der).unwrap();

    let mut verifier = SignatureVerifier::new(MessageDigest::sha256(), &ak_pub).unwrap();
    verifier.update(&quote.message).unwrap();
    let is_valid = verifier.verify(&quote.signature).unwrap();
    if !is_valid {
        panic!("quote has not been signed by ak_pub");
    }

    let (attest, _) = TpmsAttest::unmarshal(&quote.message).unwrap();

    let nonce = attest.extra_data;
    if *NONCE != *nonce {
        panic!("quote nonce does not match");
    }

    let var_data_hash = sha256(parser.var_data());
    let report_type = attestation_report.hcl_data.report_type;
    if report_type != types::SNP_REPORT_TYPE {
        panic!("attestation report type is not SEV-SNP");
    }

    let snp_report =
        SevSnpAttestationReport::from_bytes(&attestation_report.hw_report[..]).unwrap();
    if var_data_hash != snp_report.report_data[..32] {
        panic!("attestation report var data hash does not match");
    }

    let TpmuAttest::Quote(quote_info) = attest.attested else {
        panic!("attestation type is not TPM Quote");
    };

    let expected_digest = quote_info.pcr_digest;
    let mut hasher = Sha256::new();
    for pcr in &quote.pcrs {
        hasher.update(pcr);
    }
    let actual_digest = hasher.finish();
    if actual_digest != *expected_digest {
        panic!("PCR digest does not match");
    }

    let [pcr_bank] = *quote_info.pcr_select else {
        panic!("TPM quote should have 1 PCR bank selection");
    };

    if pcr_bank.hash != TpmAlgId::Sha256 {
        panic!("TPM quote should be a SHA256 PCR bank selection");
    }

    let pcr_slots: Vec<usize> = pcr_bank
        .pcr_select
        .view_bits::<Lsb0>()
        .iter_ones()
        .collect();

    let pcr_map: BTreeMap<usize, String> = pcr_slots
        .into_iter()
        .zip(quote.pcrs.iter())
        .map(|(slot, value)| (slot, hex::encode(value)))
        .collect();

    println!("claims: {pcr_map:#?}");
}
