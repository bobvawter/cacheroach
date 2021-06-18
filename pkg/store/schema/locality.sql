--  Copyright 2021 The Cockroach Authors.
--
--  Licensed under the Apache License, Version 2.0 (the "License");
--  you may not use this file except in compliance with the License.
--  You may obtain a copy of the License at
--    http://www.apache.org/licenses/LICENSE-2.0
--
--  Unless required by applicable law or agreed to in writing, software
--  distributed under the License is distributed on an "AS IS" BASIS,
--  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--  See the License for the specific language governing permissions and
--  limitations under the License.

-- This shows the desired end state for deploying Cacheroach into a
-- multi-regional CockroachDB cluster. The target database must be
-- enabled for multi-region operation.  See documentation at:
-- https://www.cockroachlabs.com/docs/stable/multiregion-overview.html

-- We would expect that the enclosing database would have
-- at least three regions defined, allowing you to then:
-- ALTER DATABASE cacheroach SURVIVE REGION FAILURE

ALTER TABLE tenants
    SET LOCALITY GLOBAL;
ALTER TABLE chunks
    SET LOCALITY GLOBAL;
ALTER TABLE ropes
    SET LOCALITY GLOBAL;
ALTER TABLE files
    SET LOCALITY GLOBAL;
ALTER TABLE principals
    SET LOCALITY GLOBAL;
ALTER TABLE vhosts
    SET LOCALITY GLOBAL;

ALTER TABLE sessions
    SET LOCALITY REGIONAL BY ROW;
ALTER TABLE uploads
    SET LOCALITY REGIONAL BY ROW;

