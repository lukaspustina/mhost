use std::time::Duration;

use ipnetwork::IpNetwork;
use nom::lib::std::collections::HashMap;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::services::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseStatus {
    Ok,
    Error,
    Maintenance,
}

#[derive(Debug, Deserialize)]
pub struct Response<T> {
    pub status: ResponseStatus,
    pub status_code: Option<usize>,
    pub version: String,
    pub cached: bool,
    pub message: Option<String>,
    pub process_time: usize,
    pub data: Option<T>,
}

#[derive(Debug, Deserialize)]
pub struct GeoLocation {
    located_resources: Vec<LocatedResource>,
}

#[derive(Debug, Deserialize)]
pub struct LocatedResource {
    resource: String,
    locations: Vec<Location>,
}

#[derive(Debug, Deserialize)]
pub struct Location {
    city: String,
    country: String,
    resources: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct NetworkInfo {
    pub asns: Vec<String>,
    pub prefix: String,
}

#[derive(Debug)]
pub struct Whois {
    pub resource: String,
    /// List of authories that have been involved in answering the request
    pub authorities: Vec<Authority>,
    /// This field should hold to whom this resource currently belongs. As every Authority uses different
    /// format, a simple heuristic is used to build this field. Basically, these are plenty of words to say,
    /// this might be horribly wrong.
    pub organization: Option<String>,
    pub country: Option<String>,
    pub cidr: Option<IpNetwork>,
    pub net_name: Option<String>,
    pub source: Option<Authority>,
}

impl From<whois::Whois> for Whois {
    fn from(w: whois::Whois) -> Self {
        Whois::from_records(w.resource, w.authorities, w.records)
    }
}

impl Whois {
    fn from_records(resource: String, authorities: Vec<Authority>, records: Vec<HashMap<String, String>>) -> Whois {
        let (organization, country, cidr, net_name, source) = whois::parse_whois_records(records);
        Whois {
            resource,
            authorities,
            organization,
            country,
            cidr,
            net_name,
            source,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Authority {
    Afrinic,
    Apnic,
    Arin,
    Iana,
    Lacnic,
    Ripe,
    Unknown,
}

impl Authority {
    pub fn from(authority: &str) -> Authority {
        use Authority::*;
        match authority.to_lowercase().as_str() {
            "afrinic" => Afrinic,
            "apnic" => Apnic,
            "arin" => Arin,
            "iana" => Iana,
            "lacnic" => Lacnic,
            "ripe" => Ripe,
            _ => Unknown,
        }
    }
}

impl From<Response<whois::Whois>> for Response<Whois> {
    fn from(whois: Response<whois::Whois>) -> Self {
        Response {
            status: whois.status,
            status_code: whois.status_code,
            version: whois.version,
            cached: whois.cached,
            message: whois.message,
            process_time: whois.process_time,
            data: whois.data.map(From::from),
        }
    }
}

mod whois {
    use std::collections::HashMap;

    use crate::services::ripe_stats::Authority;
    use chrono::prelude::*;
    use ipnetwork::IpNetwork;
    use serde::de;
    use serde::Deserialize;
    use std::str::FromStr;

    #[derive(Debug, Deserialize)]
    pub struct Whois {
        pub resource: String,
        pub authorities: Vec<super::Authority>,
        #[serde(deserialize_with = "deserialize")]
        pub records: Vec<HashMap<String, String>>,
    }

    #[derive(Debug, Deserialize)]
    struct Item {
        key: String,
        value: String,
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<HashMap<String, String>>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut result = Vec::new();
        for vec in Vec::<Vec<Item>>::deserialize(deserializer)? {
            let mut map = HashMap::new();
            for item in vec {
                let set = map.entry(item.key.to_lowercase()).or_insert_with(Vec::new);
                set.push(item.value);
            }
            let map: HashMap<String, String> = map.into_iter().map(|(k, v)| (k, v.join(", "))).collect();
            result.push(map)
        }
        Ok(result)
    }

    // This is really ugly.
    pub fn parse_whois_records(
        mut records: Vec<HashMap<String, String>>,
    ) -> (
        Option<String>,
        Option<String>,
        Option<IpNetwork>,
        Option<String>,
        Option<super::Authority>,
    ) {
        if records.is_empty() {
            return (None, None, None, None, None);
        };
        if records.len() == 1 {
            // We've received just one record table
            let records = records.pop().unwrap(); // safe unwrap
            return parse_whois_record(records);
        }
        // We have multiple tables, let's try to find the latest table.

        let mut i_dates: Vec<_> = records
            .iter()
            .enumerate()
            .map(|(i, h)| (i, h.get("regdate")))
            .filter(|(_, d)| d.is_some())
            .map(|(i, h)| (i, h.map(|x| NaiveDate::parse_from_str(x, "%Y-%m-%d").ok())))
            .map(|(i, d)| (i, d.flatten()))
            .filter(|(_, d)| d.is_some())
            .map(|(i, d)| (i, d.unwrap())) // Safe unwrap due to filter
            .collect();
        i_dates.sort_by_key(|(_, d)| *d);

        parse_whois_record(records.remove(i_dates.pop().unwrap().0)) // Safe unwrap
    }

    fn parse_whois_record(
        mut record: HashMap<String, String>,
    ) -> (
        Option<String>,
        Option<String>,
        Option<IpNetwork>,
        Option<String>,
        Option<Authority>,
    ) {
        let organization = record.remove("organization").or_else(|| record.remove("descr"));
        let country = record.remove("country");
        let cidr = record
            .remove("inetnum")
            .or_else(|| record.remove("cidr"))
            .map(|x| IpNetwork::from_str(&x).ok())
            .flatten();
        let net_name = record.remove("netname");
        let source = record.remove("source").map(|x| Authority::from(&x));
        (organization, country, cidr, net_name, source)
    }
}

pub struct RipeStatsClient {
    client: reqwest::Client,
}

impl Default for RipeStatsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RipeStatsClient {
    pub fn new() -> RipeStatsClient {
        RipeStatsClient { client: Client::new() }
    }

    pub async fn geo_location<T: Into<IpNetwork>>(&self, ip_network: T) -> Result<Response<GeoLocation>> {
        let url = "https://stat.ripe.net/data/maxmind-geo-lite/data.json";
        let resource = ip_network.into().to_string();

        self.do_call(url, &[("resource", &resource)]).await
    }

    pub async fn network_info<T: Into<IpNetwork>>(&self, ip_network: T) -> Result<Response<NetworkInfo>> {
        let url = "https://stat.ripe.net/data/network-info/data.json";
        let resource = ip_network.into().to_string();

        self.do_call(url, &[("resource", &resource)]).await
    }

    pub async fn whois<T: Into<String>>(&self, resource: T) -> Result<Response<Whois>> {
        let url = "https://stat.ripe.net/data/whois/data.json";
        let resource = resource.into();

        let response: Result<Response<whois::Whois>> = self.do_call(url, &[("resource", &resource)]).await;
        response.map(From::from)
    }

    async fn do_call<T: DeserializeOwned>(&self, url: &str, query_params: &[(&str, &str)]) -> Result<Response<T>> {
        let res = self
            .client
            .get(url)
            .timeout(Duration::from_secs(5))
            .query(query_params)
            .send()
            .await
            .map_err(|e| Error::HttpClientError {
                why: "call failed",
                source: e,
            })?;

        if !res.status().is_success() {
            return Err(Error::HttpClientErrorMessage {
                why: "unexpected status code",
                details: format!("status code: {}", res.status()),
            });
        }

        let body = res.text().await.map_err(|e| Error::HttpClientError {
            why: "reading body failed",
            source: e,
        })?;

        serde_json::from_str::<Response<T>>(&body).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use spectral::prelude::*;

    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn geo_location() {
        let client = RipeStatsClient::new();
        let ip_address = IpAddr::V4(Ipv4Addr::new(89, 0, 248, 55));

        let response = client.geo_location(ip_address).await;

        assert_that(&response).is_ok();
    }

    #[tokio::test]
    async fn network_info() {
        let client = RipeStatsClient::new();
        let ip_address = IpAddr::V4(Ipv4Addr::new(89, 0, 248, 55));

        let response = client.network_info(ip_address).await;

        assert_that(&response).is_ok();
    }

    #[tokio::test]
    async fn whois() {
        let client = RipeStatsClient::new();
        let ip_address = IpAddr::V4(Ipv4Addr::new(89, 0, 248, 55)).to_string();

        let response = client.whois(ip_address).await;

        assert_that(&response).is_ok();
    }

    #[test]
    fn parse_whois_ripe() {
        let response_json = r#"{
    "messages": [
        [
            "info",
            "IP address has been converted to a prefix"
        ]
    ],
    "see_also": [],
    "version": "4.1",
    "data_call_status": "supported - connecting to ursa",
    "cached": true,
    "data": {
        "records": [
            [
                {
                    "key": "inetnum",
                    "value": "85.197.0.0/19",
                    "details_link": "https://stat.ripe.net/85.197.0.0/19"
                },
                {
                    "key": "netname",
                    "value": "NC-DIAL-IN-POOL",
                    "details_link": null
                },
                {
                    "key": "descr",
                    "value": "NetCologne dynamic IP Pool",
                    "details_link": null
                },
                {
                    "key": "descr",
                    "value": "Am Coloneum 9",
                    "details_link": null
                },
                {
                    "key": "descr",
                    "value": "D-50829 Koeln",
                    "details_link": null
                },
                {
                    "key": "country",
                    "value": "DE",
                    "details_link": null
                },
                {
                    "key": "admin-c",
                    "value": "NC1424-RIPE",
                    "details_link": "https://rest.db.ripe.net/ripe/person-role/NC1424-RIPE"
                },
                {
                    "key": "tech-c",
                    "value": "NC1424-RIPE",
                    "details_link": "https://rest.db.ripe.net/ripe/person-role/NC1424-RIPE"
                },
                {
                    "key": "status",
                    "value": "ASSIGNED PA",
                    "details_link": null
                },
                {
                    "key": "mnt-by",
                    "value": "NETCOLOGNE-MNT",
                    "details_link": "https://rest.db.ripe.net/ripe/mntner/NETCOLOGNE-MNT"
                },
                {
                    "key": "remarks",
                    "value": "INFRA-AW",
                    "details_link": null
                },
                {
                    "key": "remarks",
                    "value": "+ + + + + + + + + + + + + + + + + + + + + + + + + + + ++ + + +",
                    "details_link": null
                },
                {
                    "key": "remarks",
                    "value": "+ abuse@netcologne.de is contact for criminal use,spam, etc. +",
                    "details_link": null
                },
                {
                    "key": "remarks",
                    "value": "+ + + + + + + + + + + + + + + + + + + + + + + + + + + ++ + + +",
                    "details_link": null
                },
                {
                    "key": "created",
                    "value": "2013-01-03T16:06:21Z",
                    "details_link": null
                },
                {
                    "key": "last-modified",
                    "value": "2013-01-03T16:06:21Z",
                    "details_link": null
                },
                {
                    "key": "source",
                    "value": "RIPE",
                    "details_link": null
                }
            ]
        ],
        "irr_records": [
            [
                {
                    "key": "route",
                    "value": "85.197.0.0/18",
                    "details_link": "https://stat.ripe.net/85.197.0.0/18"
                },
                {
                    "key": "descr",
                    "value": "NetCologne PA Space",
                    "details_link": null
                },
                {
                    "key": "origin",
                    "value": "8422",
                    "details_link": "https://stat.ripe.net/AS8422"
                },
                {
                    "key": "mnt-by",
                    "value": "NETCOLOGNE-MNT",
                    "details_link": "https://rest.db.ripe.net/ripe/mntner/NETCOLOGNE-MNT"
                },
                {
                    "key": "created",
                    "value": "2011-04-07T12:41:34Z",
                    "details_link": null
                },
                {
                    "key": "last-modified",
                    "value": "2011-04-07T12:41:34Z",
                    "details_link": null
                },
                {
                    "key": "source",
                    "value": "RIPE",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "route",
                    "value": "85.197.0.0/18",
                    "details_link": "https://stat.ripe.net/85.197.0.0/18"
                },
                {
                    "key": "descr",
                    "value": "NetCologne PA Space",
                    "details_link": null
                },
                {
                    "key": "origin",
                    "value": "8422",
                    "details_link": "https://stat.ripe.net/AS8422"
                },
                {
                    "key": "mnt-by",
                    "value": "NETCOLOGNE-MNT",
                    "details_link": null
                },
                {
                    "key": "created",
                    "value": "2011-04-07T12:41:34Z",
                    "details_link": null
                },
                {
                    "key": "last-modified",
                    "value": "2011-04-07T12:41:34Z",
                    "details_link": null
                },
                {
                    "key": "source",
                    "value": "RIPE",
                    "details_link": null
                },
                {
                    "key": "remarks",
                    "value": "* THIS OBJECT IS MODIFIED",
                    "details_link": null
                },
                {
                    "key": "remarks",
                    "value": "* Please note that all data that is generally regarded as personal",
                    "details_link": null
                },
                {
                    "key": "remarks",
                    "value": "* data has been removed from this object.",
                    "details_link": null
                },
                {
                    "key": "remarks",
                    "value": "* To view the original object, please query the RIPE Database at:",
                    "details_link": null
                },
                {
                    "key": "remarks",
                    "value": "* http://www.ripe.net/whois",
                    "details_link": null
                }
            ]
        ],
        "authorities": [
            "ripe"
        ],
        "resource": "85.197.30.30",
        "query_time": "2020-08-04T13:59:00"
    },
    "query_id": "20200804135925-d8776a2f-b362-4bbf-a4c1-737721d11414",
    "process_time": 1,
    "server_id": "app149",
    "build_version": "live.2020.8.3.57",
    "status": "ok",
    "status_code": 200,
    "time": "2020-08-04T13:59:25.555809"
}"#;

        let data: std::result::Result<Response<whois::Whois>, _> = serde_json::from_str(&response_json);
        assert_that(&data).is_ok();

        let data = data.unwrap().data;
        assert_that(&data).is_some();

        let whois: Whois = data.unwrap().into();
        assert_that(&whois.organization)
            .is_some()
            .is_equal_to("NetCologne dynamic IP Pool, Am Coloneum 9, D-50829 Koeln".to_string());
        assert_that(&whois.country).is_some().is_equal_to("DE".to_string());
        assert_that(&whois.cidr)
            .is_some()
            .is_equal_to(IpNetwork::from_str("85.197.0.0/19").unwrap());
        assert_that(&whois.net_name)
            .is_some()
            .is_equal_to("NC-DIAL-IN-POOL".to_string());
        assert_that(&whois.source).is_some().is_equal_to(&Authority::Ripe);
    }

    #[test]
    fn parse_whois_arin() {
        let response_json = r#"{
    "messages": [
        [
            "info",
            "IP address has been converted to a prefix"
        ]
    ],
    "see_also": [],
    "version": "4.1",
    "data_call_status": "supported - connecting to ursa",
    "cached": false,
    "data": {
        "records": [
            [
                {
                    "key": "NetRange",
                    "value": "18.0.0.0 - 18.255.255.255",
                    "details_link": null
                },
                {
                    "key": "CIDR",
                    "value": "18.0.0.0/8",
                    "details_link": null
                },
                {
                    "key": "NetName",
                    "value": "NET18",
                    "details_link": null
                },
                {
                    "key": "NetHandle",
                    "value": "NET-18-0-0-0-0",
                    "details_link": null
                },
                {
                    "key": "Parent",
                    "value": "()",
                    "details_link": null
                },
                {
                    "key": "NetType",
                    "value": "Allocated to ARIN",
                    "details_link": null
                },
                {
                    "key": "Organization",
                    "value": "American Registry for Internet Numbers (ARIN)",
                    "details_link": null
                },
                {
                    "key": "RegDate",
                    "value": "1994-01-01",
                    "details_link": null
                },
                {
                    "key": "Ref",
                    "value": "https://rdap.arin.net/registry/ip/18.0.0.0",
                    "details_link": "https://rdap.arin.net/registry/ip/18.0.0.0"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "NetRange",
                    "value": "18.128.0.0 - 18.255.255.255",
                    "details_link": null
                },
                {
                    "key": "CIDR",
                    "value": "18.128.0.0/9",
                    "details_link": null
                },
                {
                    "key": "NetName",
                    "value": "AT-88-Z",
                    "details_link": null
                },
                {
                    "key": "NetHandle",
                    "value": "NET-18-128-0-0-1",
                    "details_link": null
                },
                {
                    "key": "Parent",
                    "value": "NET18 (NET-18-0-0-0-0)",
                    "details_link": null
                },
                {
                    "key": "NetType",
                    "value": "Direct Allocation",
                    "details_link": null
                },
                {
                    "key": "Organization",
                    "value": "Amazon Technologies Inc. (AT-88-Z)",
                    "details_link": null
                },
                {
                    "key": "RegDate",
                    "value": "2018-06-29",
                    "details_link": null
                },
                {
                    "key": "Ref",
                    "value": "https://rdap.arin.net/registry/ip/18.128.0.0",
                    "details_link": "https://rdap.arin.net/registry/ip/18.128.0.0"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "NetRange",
                    "value": "18.128.0.0 - 18.255.255.255",
                    "details_link": null
                },
                {
                    "key": "CIDR",
                    "value": "18.128.0.0/9",
                    "details_link": null
                },
                {
                    "key": "NetName",
                    "value": "AT-88-Z",
                    "details_link": null
                },
                {
                    "key": "NetHandle",
                    "value": "NET-18-128-0-0-1",
                    "details_link": null
                },
                {
                    "key": "Parent",
                    "value": "NET18 (NET-18-0-0-0-0)",
                    "details_link": null
                },
                {
                    "key": "NetType",
                    "value": "Direct Allocation",
                    "details_link": null
                },
                {
                    "key": "Organization",
                    "value": "Amazon Technologies Inc. (AT-88-Z)",
                    "details_link": null
                },
                {
                    "key": "RegDate",
                    "value": "2018-06-29",
                    "details_link": null
                },
                {
                    "key": "Ref",
                    "value": "https://rdap.arin.net/registry/ip/18.128.0.0",
                    "details_link": "https://rdap.arin.net/registry/ip/18.128.0.0"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "NetRange",
                    "value": "18.194.0.0 - 18.195.255.255",
                    "details_link": null
                },
                {
                    "key": "CIDR",
                    "value": "18.194.0.0/15",
                    "details_link": null
                },
                {
                    "key": "NetName",
                    "value": "AMAZO-ZFRA",
                    "details_link": null
                },
                {
                    "key": "NetHandle",
                    "value": "NET-18-194-0-0-2",
                    "details_link": null
                },
                {
                    "key": "Parent",
                    "value": "AT-88-Z (NET-18-128-0-0-1)",
                    "details_link": null
                },
                {
                    "key": "NetType",
                    "value": "Reallocated",
                    "details_link": null
                },
                {
                    "key": "OriginAS",
                    "value": "AS16509",
                    "details_link": null
                },
                {
                    "key": "Organization",
                    "value": "A100 ROW GmbH (RG-123)",
                    "details_link": null
                },
                {
                    "key": "RegDate",
                    "value": "2017-05-25",
                    "details_link": null
                },
                {
                    "key": "Ref",
                    "value": "https://rdap.arin.net/registry/ip/18.194.0.0",
                    "details_link": "https://rdap.arin.net/registry/ip/18.194.0.0"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgAbuseHandle",
                    "value": "AEA8-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgAbuseName",
                    "value": "Amazon EC2 Abuse",
                    "details_link": null
                },
                {
                    "key": "OrgAbusePhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgAbuseEmail",
                    "value": "abuse@amazonaws.com",
                    "details_link": "mailto:abuse@amazonaws.com"
                },
                {
                    "key": "OrgAbuseRef",
                    "value": "https://rdap.arin.net/registry/entity/AEA8-ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/AEA8-ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgAbuseHandle",
                    "value": "AEA8-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgAbuseName",
                    "value": "Amazon EC2 Abuse",
                    "details_link": null
                },
                {
                    "key": "OrgAbusePhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgAbuseEmail",
                    "value": "abuse@amazonaws.com",
                    "details_link": "mailto:abuse@amazonaws.com"
                },
                {
                    "key": "OrgAbuseRef",
                    "value": "https://rdap.arin.net/registry/entity/AEA8-ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/AEA8-ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgAbuseHandle",
                    "value": "AEA8-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgAbuseName",
                    "value": "Amazon EC2 Abuse",
                    "details_link": null
                },
                {
                    "key": "OrgAbusePhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgAbuseEmail",
                    "value": "abuse@amazonaws.com",
                    "details_link": "mailto:abuse@amazonaws.com"
                },
                {
                    "key": "OrgAbuseRef",
                    "value": "https://rdap.arin.net/registry/entity/AEA8-ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/AEA8-ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgAbuseHandle",
                    "value": "ARIN-HOSTMASTER",
                    "details_link": null
                },
                {
                    "key": "OrgAbuseName",
                    "value": "Registration Services Department",
                    "details_link": null
                },
                {
                    "key": "OrgAbusePhone",
                    "value": "+1-703-227-0660",
                    "details_link": null
                },
                {
                    "key": "OrgAbuseEmail",
                    "value": "hostmaster@arin.net",
                    "details_link": "mailto:hostmaster@arin.net"
                },
                {
                    "key": "OrgAbuseRef",
                    "value": "https://rdap.arin.net/registry/entity/ARIN-HOSTMASTER",
                    "details_link": "https://rdap.arin.net/registry/entity/ARIN-HOSTMASTER"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgNOCHandle",
                    "value": "AANO1-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgNOCName",
                    "value": "Amazon AWS Network Operations",
                    "details_link": null
                },
                {
                    "key": "OrgNOCPhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgNOCEmail",
                    "value": "amzn-noc-contact@amazon.com",
                    "details_link": "mailto:amzn-noc-contact@amazon.com"
                },
                {
                    "key": "OrgNOCRef",
                    "value": "https://rdap.arin.net/registry/entity/AANO1-ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/AANO1-ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgNOCHandle",
                    "value": "AANO1-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgNOCName",
                    "value": "Amazon AWS Network Operations",
                    "details_link": null
                },
                {
                    "key": "OrgNOCPhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgNOCEmail",
                    "value": "amzn-noc-contact@amazon.com",
                    "details_link": "mailto:amzn-noc-contact@amazon.com"
                },
                {
                    "key": "OrgNOCRef",
                    "value": "https://rdap.arin.net/registry/entity/AANO1-ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/AANO1-ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgNOCHandle",
                    "value": "AANO1-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgNOCName",
                    "value": "Amazon AWS Network Operations",
                    "details_link": null
                },
                {
                    "key": "OrgNOCPhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgNOCEmail",
                    "value": "amzn-noc-contact@amazon.com",
                    "details_link": "mailto:amzn-noc-contact@amazon.com"
                },
                {
                    "key": "OrgNOCRef",
                    "value": "https://rdap.arin.net/registry/entity/AANO1-ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/AANO1-ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgNOCHandle",
                    "value": "ARINN-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgNOCName",
                    "value": "ARIN NOC",
                    "details_link": null
                },
                {
                    "key": "OrgNOCPhone",
                    "value": "+1-703-227-9840",
                    "details_link": null
                },
                {
                    "key": "OrgNOCEmail",
                    "value": "noc@arin.net",
                    "details_link": "mailto:noc@arin.net"
                },
                {
                    "key": "OrgNOCRef",
                    "value": "https://rdap.arin.net/registry/entity/ARINN-ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/ARINN-ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgName",
                    "value": "A100 ROW GmbH",
                    "details_link": null
                },
                {
                    "key": "OrgId",
                    "value": "RG-123",
                    "details_link": null
                },
                {
                    "key": "Address",
                    "value": "Marcel-Breuer-Strasse 10",
                    "details_link": null
                },
                {
                    "key": "City",
                    "value": "Munchen",
                    "details_link": null
                },
                {
                    "key": "PostalCode",
                    "value": "80807",
                    "details_link": null
                },
                {
                    "key": "Country",
                    "value": "DE",
                    "details_link": null
                },
                {
                    "key": "RegDate",
                    "value": "2014-11-07",
                    "details_link": null
                },
                {
                    "key": "Ref",
                    "value": "https://rdap.arin.net/registry/entity/RG-123",
                    "details_link": "https://rdap.arin.net/registry/entity/RG-123"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgName",
                    "value": "Amazon Technologies Inc.",
                    "details_link": null
                },
                {
                    "key": "OrgId",
                    "value": "AT-88-Z",
                    "details_link": null
                },
                {
                    "key": "Address",
                    "value": "410 Terry Ave N.",
                    "details_link": null
                },
                {
                    "key": "City",
                    "value": "Seattle",
                    "details_link": null
                },
                {
                    "key": "StateProv",
                    "value": "WA",
                    "details_link": null
                },
                {
                    "key": "PostalCode",
                    "value": "98109",
                    "details_link": null
                },
                {
                    "key": "Country",
                    "value": "US",
                    "details_link": null
                },
                {
                    "key": "RegDate",
                    "value": "2011-12-08",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "All abuse reports MUST include:",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* src IP",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* dest IP (your IP)",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* dest port",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* Accurate date/timestamp and timezone of activity",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* Intensity/frequency (short log extracts)",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* Your contact details (phone and email) Without these we will be unable to identify the correct owner of the IP address at that point in time.",
                    "details_link": null
                },
                {
                    "key": "Ref",
                    "value": "https://rdap.arin.net/registry/entity/AT-88-Z",
                    "details_link": "https://rdap.arin.net/registry/entity/AT-88-Z"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgName",
                    "value": "Amazon Technologies Inc.",
                    "details_link": null
                },
                {
                    "key": "OrgId",
                    "value": "AT-88-Z",
                    "details_link": null
                },
                {
                    "key": "Address",
                    "value": "410 Terry Ave N.",
                    "details_link": null
                },
                {
                    "key": "City",
                    "value": "Seattle",
                    "details_link": null
                },
                {
                    "key": "StateProv",
                    "value": "WA",
                    "details_link": null
                },
                {
                    "key": "PostalCode",
                    "value": "98109",
                    "details_link": null
                },
                {
                    "key": "Country",
                    "value": "US",
                    "details_link": null
                },
                {
                    "key": "RegDate",
                    "value": "2011-12-08",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "All abuse reports MUST include:",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* src IP",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* dest IP (your IP)",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* dest port",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* Accurate date/timestamp and timezone of activity",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* Intensity/frequency (short log extracts)",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "* Your contact details (phone and email) Without these we will be unable to identify the correct owner of the IP address at that point in time.",
                    "details_link": null
                },
                {
                    "key": "Ref",
                    "value": "https://rdap.arin.net/registry/entity/AT-88-Z",
                    "details_link": "https://rdap.arin.net/registry/entity/AT-88-Z"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgName",
                    "value": "American Registry for Internet Numbers",
                    "details_link": null
                },
                {
                    "key": "OrgId",
                    "value": "ARIN",
                    "details_link": null
                },
                {
                    "key": "Address",
                    "value": "PO Box 232290",
                    "details_link": null
                },
                {
                    "key": "City",
                    "value": "Centreville",
                    "details_link": null
                },
                {
                    "key": "StateProv",
                    "value": "VA",
                    "details_link": null
                },
                {
                    "key": "PostalCode",
                    "value": "20120",
                    "details_link": null
                },
                {
                    "key": "Country",
                    "value": "US",
                    "details_link": null
                },
                {
                    "key": "RegDate",
                    "value": "1997-12-22",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "For abuse issues please see URL:",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "https://www.arin.net/reference/materials/abuse/",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "The Registration Services Help Desk is open",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "from 7 a.m. to 7 p.m., U.S. Eastern time to assist you.",
                    "details_link": null
                },
                {
                    "key": "Comment",
                    "value": "Phone Number: (703) 227-0660; Fax Number: (703) 997-8844.",
                    "details_link": null
                },
                {
                    "key": "Ref",
                    "value": "https://rdap.arin.net/registry/entity/ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgRoutingHandle",
                    "value": "ADR29-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingName",
                    "value": "AWS Dogfish Routing",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingPhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingEmail",
                    "value": "aws-dogfish-routing-poc@amazon.com",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingRef",
                    "value": "https://rdap.arin.net/registry/entity/ADR29-ARIN",
                    "details_link": null
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgRoutingHandle",
                    "value": "ADR29-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingName",
                    "value": "AWS Dogfish Routing",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingPhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingEmail",
                    "value": "aws-dogfish-routing-poc@amazon.com",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingRef",
                    "value": "https://rdap.arin.net/registry/entity/ADR29-ARIN",
                    "details_link": null
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgRoutingHandle",
                    "value": "IPROU3-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingName",
                    "value": "IP Routing",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingPhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingEmail",
                    "value": "aws-routing-poc@amazon.com",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingRef",
                    "value": "https://rdap.arin.net/registry/entity/IPROU3-ARIN",
                    "details_link": null
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgRoutingHandle",
                    "value": "IPROU3-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingName",
                    "value": "IP Routing",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingPhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingEmail",
                    "value": "aws-routing-poc@amazon.com",
                    "details_link": null
                },
                {
                    "key": "OrgRoutingRef",
                    "value": "https://rdap.arin.net/registry/entity/IPROU3-ARIN",
                    "details_link": null
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgTechHandle",
                    "value": "ANO24-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgTechName",
                    "value": "Amazon EC2 Network Operations",
                    "details_link": null
                },
                {
                    "key": "OrgTechPhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgTechEmail",
                    "value": "amzn-noc-contact@amazon.com",
                    "details_link": "mailto:amzn-noc-contact@amazon.com"
                },
                {
                    "key": "OrgTechRef",
                    "value": "https://rdap.arin.net/registry/entity/ANO24-ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/ANO24-ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgTechHandle",
                    "value": "ANO24-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgTechName",
                    "value": "Amazon EC2 Network Operations",
                    "details_link": null
                },
                {
                    "key": "OrgTechPhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgTechEmail",
                    "value": "amzn-noc-contact@amazon.com",
                    "details_link": "mailto:amzn-noc-contact@amazon.com"
                },
                {
                    "key": "OrgTechRef",
                    "value": "https://rdap.arin.net/registry/entity/ANO24-ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/ANO24-ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgTechHandle",
                    "value": "ANO24-ARIN",
                    "details_link": null
                },
                {
                    "key": "OrgTechName",
                    "value": "Amazon EC2 Network Operations",
                    "details_link": null
                },
                {
                    "key": "OrgTechPhone",
                    "value": "+1-206-266-4064",
                    "details_link": null
                },
                {
                    "key": "OrgTechEmail",
                    "value": "amzn-noc-contact@amazon.com",
                    "details_link": "mailto:amzn-noc-contact@amazon.com"
                },
                {
                    "key": "OrgTechRef",
                    "value": "https://rdap.arin.net/registry/entity/ANO24-ARIN",
                    "details_link": "https://rdap.arin.net/registry/entity/ANO24-ARIN"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ],
            [
                {
                    "key": "OrgTechHandle",
                    "value": "ARIN-HOSTMASTER",
                    "details_link": null
                },
                {
                    "key": "OrgTechName",
                    "value": "Registration Services Department",
                    "details_link": null
                },
                {
                    "key": "OrgTechPhone",
                    "value": "+1-703-227-0660",
                    "details_link": null
                },
                {
                    "key": "OrgTechEmail",
                    "value": "hostmaster@arin.net",
                    "details_link": "mailto:hostmaster@arin.net"
                },
                {
                    "key": "OrgTechRef",
                    "value": "https://rdap.arin.net/registry/entity/ARIN-HOSTMASTER",
                    "details_link": "https://rdap.arin.net/registry/entity/ARIN-HOSTMASTER"
                },
                {
                    "key": "source",
                    "value": "ARIN",
                    "details_link": null
                }
            ]
        ],
        "irr_records": [
            [
                {
                    "key": "route",
                    "value": "18.194.0.0/15",
                    "details_link": "https://stat.ripe.net/18.194.0.0/15"
                },
                {
                    "key": "descr",
                    "value": "Amazon EC2 FRA prefix",
                    "details_link": null
                },
                {
                    "key": "origin",
                    "value": "16509",
                    "details_link": "https://stat.ripe.net/AS16509"
                },
                {
                    "key": "mnt-by",
                    "value": "MAINT-AS16509",
                    "details_link": null
                },
                {
                    "key": "source",
                    "value": "RADB",
                    "details_link": null
                }
            ]
        ],
        "authorities": [
            "arin"
        ],
        "resource": "18.194.27.178",
        "query_time": "2020-08-04T14:31:00"
    },
    "query_id": "20200804143106-0a30f84d-912f-49b8-8ac1-c44421126d17",
    "process_time": 1541,
    "server_id": "app144",
    "build_version": "live.2020.8.3.57",
    "status": "ok",
    "status_code": 200,
    "time": "2020-08-04T14:31:08.371010"
}"#;
        let data: std::result::Result<Response<whois::Whois>, _> = serde_json::from_str(&response_json);
        assert_that(&data).is_ok();

        let data = data.unwrap().data;
        assert_that(&data).is_some();

        let whois: Whois = data.unwrap().into();
        assert_that(&whois.organization)
            .is_some()
            .is_equal_to("Amazon Technologies Inc. (AT-88-Z)".to_string());
        assert_that(&whois.country).is_none();
        assert_that(&whois.cidr)
            .is_some()
            .is_equal_to(IpNetwork::from_str("18.128.0.0/9").unwrap());
        assert_that(&whois.net_name)
            .is_some()
            .is_equal_to("AT-88-Z".to_string());
        assert_that(&whois.source).is_some().is_equal_to(&Authority::Arin);
    }
}
