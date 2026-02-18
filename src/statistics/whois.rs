// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::marker::PhantomData;

use crate::services::whois::WhoisResponses;

use super::*;

#[derive(Debug)]
pub struct WhoisStats<'a> {
    pub responses: usize,
    pub geo_locations: usize,
    pub network_infos: usize,
    pub whois: usize,
    pub errors: usize,
    // This is used to please the borrow checker as we currently don't use a borrowed value with lifetime 'a
    phantom: PhantomData<&'a usize>,
}

impl<'a> Statistics<'a> for WhoisResponses {
    type StatsOut = WhoisStats<'a>;

    fn statistics(&'a self) -> Self::StatsOut {
        WhoisStats {
            responses: self.iter().count(),
            geo_locations: self.geo_location().count(),
            network_infos: self.network_info().count(),
            whois: self.whois().count(),
            errors: self.err().count(),
            phantom: PhantomData,
        }
    }
}
