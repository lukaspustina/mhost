// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use nom::Err;
use nom::error::Error as NomError;

use crate::{Error, Result};

#[derive(Debug, PartialEq)]
pub struct MtaSts<'a> {
    version: &'a str,
    id: &'a str,
}

#[allow(clippy::should_implement_trait)]
impl<'a> MtaSts<'a> {
    pub fn from_str(txt: &'a str) -> Result<MtaSts<'a>> {
        match parser::mta_sts(txt) {
            Ok((_, result)) => Ok(result),
            Err(Err::Incomplete(_)) => Err(Error::ParserError {
                what: txt.to_string(),
                to: "MTA-STS TXT Record",
                why: "input is incomplete".to_string(),
            }),
            Err(Err::Error(NomError { input: what, code: why })) | Err(Err::Failure(NomError { input: what, code: why })) => Err(Error::ParserError {
                what: what.to_string(),
                to: "MTA-STS TXT Record",
                why: format!("{:?}", why),
            }),
        }
    }

    pub fn version(&self) -> &str {
        self.version
    }

    pub fn id(&self) -> &str {
        self.id
    }
}

pub(crate) mod parser {
    use super::MtaSts;
    use crate::resources::rdata::parsed_txt::tag_value;
    use nom::error::{Error as NomError, ErrorKind};
    use nom::{Err, IResult};

    pub fn mta_sts(input: &str) -> IResult<&str, MtaSts<'_>> {
        let (rest, tags) = tag_value::parser::tag_list(input)?;

        // First tag must be v=STSv1
        let version = tags.first().map(|(k, v)| (*k, *v));
        match version {
            Some(("v", "STSv1")) => {}
            _ => return Err(Err::Error(NomError::new(input, ErrorKind::Tag))),
        }

        // id= is required
        let id = tags.iter().find(|(k, _)| *k == "id").map(|(_, v)| *v);
        let id = match id {
            Some(id) => id,
            None => return Err(Err::Error(NomError::new(input, ErrorKind::Tag))),
        };

        Ok((
            rest,
            MtaSts {
                version: "STSv1",
                id,
            },
        ))
    }
}

#[cfg(test)]
mod test {
    use super::parser::mta_sts;
    use super::*;

    #[test]
    fn valid_record() {
        crate::utils::tests::logging::init();
        let record = "v=STSv1; id=20190429T010101";

        let (_, result) = mta_sts(record).expect("failed to parse MTA-STS record");

        assert_eq!(result.version(), "STSv1");
        assert_eq!(result.id(), "20190429T010101");
    }

    #[test]
    fn alphanumeric_id() {
        crate::utils::tests::logging::init();
        let record = "v=STSv1; id=abc123xyz";

        let (_, result) = mta_sts(record).expect("failed to parse MTA-STS record");

        assert_eq!(result.id(), "abc123xyz");
    }

    #[test]
    fn invalid_version() {
        crate::utils::tests::logging::init();
        let record = "v=STSv2; id=abc123";

        let res = mta_sts(record);

        assert!(res.is_err());
    }

    #[test]
    fn missing_id() {
        crate::utils::tests::logging::init();
        let record = "v=STSv1";

        let res = mta_sts(record);

        assert!(res.is_err());
    }
}
