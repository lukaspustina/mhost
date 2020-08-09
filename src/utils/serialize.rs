use crate::nameserver::NameServerConfig;

use serde::Serializer;
use std::sync::Arc;

pub(crate) fn ser_arc_nameserver_config<S>(data: &Arc<NameServerConfig>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&data.to_string())
}

pub(crate) fn ser_to_string<S, T: ToString>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&data.to_string())
}
