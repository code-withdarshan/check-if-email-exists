use serde::Serialize;
use serde_json::Value;
use std::convert::TryFrom;

#[derive(Debug)]
pub struct CsvWrapper(pub Value);

/// Missing checks remain empty cells instead of being reported as false.
#[derive(Debug, Serialize)]
pub struct CsvResponse {
	input: String,
	is_reachable: String,
	#[serde(rename = "misc.is_disposable")]
	misc_is_disposable: Option<bool>,
	#[serde(rename = "misc.is_role_account")]
	misc_is_role_account: Option<bool>,
	#[serde(rename = "misc.gravatar_url")]
	misc_gravatar_url: Option<String>,
	#[serde(rename = "mx.accepts_mail")]
	mx_accepts_mail: Option<bool>,
	#[serde(rename = "smtp.can_connect")]
	smtp_can_connect: Option<bool>,
	#[serde(rename = "smtp.has_full_inbox")]
	smtp_has_full_inbox: Option<bool>,
	#[serde(rename = "smtp.is_catch_all")]
	smtp_is_catch_all: Option<bool>,
	#[serde(rename = "smtp.is_deliverable")]
	smtp_is_deliverable: Option<bool>,
	#[serde(rename = "smtp.is_disabled")]
	smtp_is_disabled: Option<bool>,
	#[serde(rename = "syntax.is_valid_syntax")]
	syntax_is_valid_syntax: Option<bool>,
	#[serde(rename = "syntax.domain")]
	syntax_domain: Option<String>,
	#[serde(rename = "syntax.username")]
	syntax_username: Option<String>,
	error: Option<String>,
}
impl TryFrom<CsvWrapper> for CsvResponse {
	type Error = &'static str;
	fn try_from(value: CsvWrapper) -> Result<Self, Self::Error> {
		let v = value.0;
		let input = v["input"]
			.as_str()
			.ok_or("input should be a string")?
			.to_owned();
		let is_reachable = v["is_reachable"]
			.as_str()
			.ok_or("is_reachable should be a string")?
			.to_owned();
		let errors: Vec<String> = [
			"/error",
			"/misc/error",
			"/mx/error",
			"/smtp/error",
			"/syntax/error",
		]
		.iter()
		.filter_map(|path| v.pointer(path))
		.filter(|e| !e.is_null())
		.map(|e| {
			e.as_str()
				.map(str::to_owned)
				.unwrap_or_else(|| e.to_string())
		})
		.collect();
		Ok(Self {
			input,
			is_reachable,
			misc_is_disposable: v["misc"]["is_disposable"].as_bool(),
			misc_is_role_account: v["misc"]["is_role_account"].as_bool(),
			misc_gravatar_url: v["misc"]["gravatar_url"].as_str().map(str::to_owned),
			mx_accepts_mail: v["mx"]["accepts_mail"].as_bool(),
			smtp_can_connect: v["smtp"]["can_connect_smtp"].as_bool(),
			smtp_has_full_inbox: v["smtp"]["has_full_inbox"].as_bool(),
			smtp_is_catch_all: v["smtp"]["is_catch_all"].as_bool(),
			smtp_is_deliverable: v["smtp"]["is_deliverable"].as_bool(),
			smtp_is_disabled: v["smtp"]["is_disabled"].as_bool(),
			syntax_is_valid_syntax: v["syntax"]["is_valid_syntax"].as_bool(),
			syntax_domain: v["syntax"]["domain"].as_str().map(str::to_owned),
			syntax_username: v["syntax"]["username"].as_str().map(str::to_owned),
			error: if errors.is_empty() {
				None
			} else {
				Some(errors.join("; "))
			},
		})
	}
}
#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;
	#[test]
	fn exports_current_mx_field_and_nested_errors() {
		let row = CsvResponse::try_from(CsvWrapper(json!({
			"input": "test@example.org", "is_reachable": "unknown",
			"mx": {"accepts_mail": true}, "smtp": {"error": "timeout"}
		})))
		.unwrap();
		assert_eq!(row.mx_accepts_mail, Some(true));
		assert_eq!(row.smtp_is_deliverable, None);
		assert_eq!(row.error.as_deref(), Some("timeout"));
		let mut writer = csv::Writer::from_writer(Vec::new());
		writer.serialize(row).unwrap();
		let bytes = writer.into_inner().unwrap();
		let mut reader = csv::Reader::from_reader(bytes.as_slice());
		let headers = reader.headers().unwrap().clone();
		let record = reader.records().next().unwrap().unwrap();
		let mx = headers.iter().position(|h| h == "mx.accepts_mail").unwrap();
		assert_eq!(&record[mx], "true");
	}
	#[test]
	fn exports_terminal_task_failures() {
		let row = CsvResponse::try_from(CsvWrapper(json!({
			"input": "test@example.org", "is_reachable": "unknown", "error": "worker timeout"
		})))
		.unwrap();
		assert_eq!(row.error.as_deref(), Some("worker timeout"));
		assert_eq!(row.mx_accepts_mail, None);
	}
	#[test]
	fn exports_actual_core_response() {
		let output = check_if_email_exists::CheckEmailOutput::default();
		CsvResponse::try_from(CsvWrapper(serde_json::to_value(output).unwrap())).unwrap();
	}
}
