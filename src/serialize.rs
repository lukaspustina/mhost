use crate::nameserver::NameServerConfig;
use crate::Error;

use serde::Serializer;
use std::sync::Arc;

pub(crate) fn ser_arc_nameserver_config<S>(data: &Arc<NameServerConfig>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&data.to_string())
}

pub(crate) fn ser_error<S>(data: &Error, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&data.to_string())
}

