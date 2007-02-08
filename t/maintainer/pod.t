#!perl

use strict;
use Test::More;
eval "use Test::Pod 1.14";
plan(skip_all => "Test::Pod 1.14 required for testing POD"), exit if $@;
plan(skip_all => "no POD (yet?)"), exit if ! all_pod_files();
all_pod_files_ok();

