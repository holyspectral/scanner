package cvetools

import (
	"testing"

	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/common"
)

type versionTestCase struct {
	result  bool
	version string
	dbVer   []common.AppModuleVersion
}

func TestAffectedVersion(t *testing.T) {
	cases := []versionTestCase{
		{result: false, version: "1.2.3", dbVer: []common.AppModuleVersion{}},
		{result: true, version: "1.2.3", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}}},
		{result: false, version: "1.2.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}}},
		{result: true, version: "4.0.1", dbVer: []common.AppModuleVersion{{OpCode: "", Version: "4.0.1"}}},
		{result: true, version: "1.2.3", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "gt", Version: "1.2.0"}}},
		{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "gt", Version: "1.2.0"}, {OpCode: "orlt", Version: "1.3.5"}}},
		{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "gt", Version: "1.2.0"}, {OpCode: "lt", Version: "1.3.5"}}},
		{result: false, version: "1.3.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "lt", Version: "1.3.5"}}},
		{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "orlt", Version: "1.3.5"}}},
		{result: true, version: "1.3.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "orlt", Version: "1.3.5"}, {OpCode: "gteq", Version: "1.3.4"}}},
		{result: false, version: "1.3.3", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "orlt", Version: "1.3.5"}, {OpCode: "gteq", Version: "1.3.4"}}},
		{result: true, version: "1.1.1", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}}},
		{result: false, version: "1.1.1", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4,1.2"}}},
		{result: true, version: "1.3.6", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "lt", Version: "1.3.7"}, {OpCode: "gt", Version: "1.3.5"}}},
		{result: true, version: "1.3.6", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "1.2.4"}, {OpCode: "orlt", Version: "1.3.7"}, {OpCode: "gt", Version: "1.3.5"}}},
		{result: false, version: "2.9.1-6.el7.4", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "2.9.1-6.el7_2.2"}}},
		{result: false, version: "4.18.0-193.19.1.el8_2", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.18.0-193.19.1.el8"}}},
		{result: false, version: "4.18.0-193.19.1.el8_2", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.18.0-193.el8"}}},
		{result: true, version: "4.18.0-193.19.1.el8", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.18.0-193.19.1.el8_2"}}},
		{result: false, version: "4.18.0.el8_2", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "4.18.0.el8"}}},
		{result: false, version: "5.2.4.5", dbVer: []common.AppModuleVersion{{OpCode: "lt", Version: "5.2.4.3,5.2"}, {OpCode: "orlt", Version: "6.0.3.1"}}},
		{result: true, version: "5.2.4.5", dbVer: []common.AppModuleVersion{{OpCode: "gteq", Version: "5.2.4.3,5.2"}, {OpCode: "orgteq", Version: "6.0.3.1"}}},
		{result: false, version: "5.0.11", dbVer: []common.AppModuleVersion{{OpCode: "gteq", Version: "5.0"}, {OpCode: "lteq", Version: "5.0.8"}, {OpCode: "orgteq", Version: "2.1"}, {OpCode: "lteq", Version: "2.1.28"}, {OpCode: "orgteq", Version: "3.1"}, {OpCode: "lteq", Version: "3.1.17"}, {OpCode: "orgteq", Version: "7.0"}, {OpCode: "lt", Version: "7.0.7"}, {OpCode: "orgteq", Version: "7.1"}, {OpCode: "lt", Version: "7.1.4"}}},
	}

	for _, c := range cases {
		v, _ := utils.NewVersion(c.version)
		if v.String() != c.version {
			t.Errorf("Error parsing version:  %v => %v", c.version, v.String())
		}
		ret := compareAppVersion(c.version, c.dbVer)
		if ret != c.result {
			t.Errorf("package %v, affected %v => %v", c.version, c.dbVer, ret)
		}
	}
}

func TestFixedVersion(t *testing.T) {
	cases := []versionTestCase{
		{result: true, version: "4.0.2", dbVer: []common.AppModuleVersion{{OpCode: "gteq", Version: "2.12.5"}, {OpCode: "lt", Version: "3.0.0"}, {OpCode: "orgteq", Version: "3.7.2"}, {OpCode: "lt", Version: "4.0.0"}, {OpCode: "orgteq", Version: "4.0.0.beta8"}}},
	}
	for _, c := range cases {
		v, _ := utils.NewVersion(c.version)
		if v.String() != c.version {
			t.Errorf("Error parsing version:  %v => %v", c.version, v.String())
		}
		ret := compareAppVersion(c.version, c.dbVer)
		if ret != c.result {
			t.Errorf("package %v, fixed %v => %v", c.version, c.dbVer, ret)
		}
	}
}
