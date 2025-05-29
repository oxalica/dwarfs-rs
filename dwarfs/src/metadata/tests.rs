use super::*;

#[test]
#[cfg(feature = "serialize")]
fn serde_schema() {
    let schema = Schema {
        relax_type_checks: true,
        layouts: DenseMap(vec![Some(SchemaLayout {
            size: 1,
            bits: 0,
            fields: DenseMap::default(),
            type_name: String::new(),
        })]),
        root_layout: 0,
        file_version: 1,
    };
    let bytes = schema.to_bytes().unwrap();

    let expect = [
        // struct
        0x11, // field `relax_type_checks` (id = 1), value = true
        0x1b, // field `layouts` (id = 0 + 1 = 1), type = 0xb map
        0x01, //   map size = 1
        0x4c, //   key = i16, value = struct
        0x00, //     key i16 = 0 = zigzag(0)
        /**/  //     value struct
        0x15, //       field `size` (id = 0 + 1 = 1)
        0x02, //         2 = zigzag(1)
        0x2b, //       field `fields` (id = 1 + 2 = 3), type = 0xb map
        0x00, //         len = 0
        0x18, //       field `type_name` (id = 3 + 1 = 4), type = 0x8 binary
        0x00, //         len = 0
        0x00, //     struct end
        0x25, // field `field_version` (id = 1 + 2 = 3), type = 0x5 i32
        0x02, //   2 = zigzag(1)
        0x00, // struct end
    ];
    assert_eq!(bytes, expect);

    let got = Schema::parse(&bytes).unwrap();
    assert_eq!(got, schema);
}

#[test]
fn de_frozen() {
    #[derive(Debug, PartialEq, Eq, Deserialize)]
    struct Pair {
        a: u32,
        #[serde(default)]
        b: u32,
        c: u32,
    }

    let schema = Schema {
        relax_type_checks: true,
        layouts: DenseMap(vec![
            None,
            Some(SchemaLayout {
                size: 0,
                bits: 8,
                fields: DenseMap(vec![
                    None,
                    Some(SchemaField {
                        layout_id: 2,
                        offset: 0,
                    }),
                    None,
                    Some(SchemaField {
                        layout_id: 2,
                        offset: -4,
                    }),
                ]),
                type_name: String::new(),
            }),
            Some(SchemaLayout {
                size: 0,
                bits: 4,
                fields: DenseMap::default(),
                type_name: String::new(),
            }),
        ]),
        root_layout: 1,
        file_version: 1,
    };

    let de = de_frozen::deserialize::<Pair>(&schema, b"\x42\0\0\0\0\0\0\0").unwrap();
    assert_eq!(
        de,
        Pair {
            a: 0x2,
            b: 0,
            c: 0x4
        }
    );
}
