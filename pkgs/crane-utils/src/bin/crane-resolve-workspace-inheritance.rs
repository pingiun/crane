use anyhow::Context;
use serde::Deserialize;
use std::{
    env,
    fs::File,
    io::{stdout, Read, Write},
    mem,
    path::Path,
    process::{Command, Stdio},
    str::FromStr,
};
use toml_edit::Item;

fn main() {
    let mut args = env::args();

    let _ = args.next(); // Skip our name

    let cargo_toml = args
        .next()
        .expect("please specify a path to a Cargo.toml file");
    let cargo_toml = Path::new(&cargo_toml);

    args.for_each(|arg| eprintln!("ignoring argument: {arg}"));

    env::set_current_dir(cargo_toml.parent().expect("can't cd into Cargo.toml dir"))
        .expect("can't cd into Cargo.toml dir");

    if let Err(err) = resolve_and_print_cargo_toml(cargo_toml) {
        eprintln!("ignoring error in resolving workspace inheritance: {err:?}");
    }
}

#[derive(Deserialize)]
struct CargoMetadata {
    workspace_root: String,
}

fn resolve_and_print_cargo_toml(cargo_toml: &Path) -> anyhow::Result<()> {
    let root_toml = Command::new("cargo")
        .arg("metadata")
        .arg("--no-deps")
        .arg("--format-version")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .context("failed to get cargo metadata")
        .and_then(|output| {
            if output.status.success() {
                serde_json::from_slice::<CargoMetadata>(&output.stdout)
                    .map(|metadata| metadata.workspace_root)
                    .context("cannot parse Cargo.toml")
            } else {
                anyhow::bail!("`cargo metadata` failed")
            }
        })?;

    let root_toml = Path::new(&root_toml);
    if !root_toml.exists() {
        anyhow::bail!("cannot read workspace root Cargo.toml");
    }

    let mut cargo_toml = parse_toml(cargo_toml)?;
    merge(&mut cargo_toml, &parse_toml(&root_toml.join("Cargo.toml"))?);

    stdout()
        .write_all(cargo_toml.to_string().as_bytes())
        .context("failed to print updated Cargo.toml")
}

fn parse_toml(path: &Path) -> anyhow::Result<toml_edit::Document> {
    let mut buf = String::new();
    File::open(path)
        .and_then(|mut file| file.read_to_string(&mut buf))
        .with_context(|| format!("cannot read {}", path.display()))?;

    toml_edit::Document::from_str(&buf).with_context(|| format!("cannot parse {}", path.display()))
}

/// Merge the workspace `root` toml into the specified crate's `cargo_toml`
fn merge(cargo_toml: &mut toml_edit::Document, root: &toml_edit::Document) {
    let w: &dyn toml_edit::TableLike =
        if let Some(w) = root.get("workspace").and_then(try_as_table_like) {
            w
        } else {
            // no "workspace" entry, nothing to merge
            return;
        };

    // https://doc.rust-lang.org/cargo/reference/workspaces.html#workspaces
    for (key, ws_key, inherit) in [
        ("package", "package", false),
        ("dependencies", "dependencies", false),
        ("dev-dependencies", "dependencies", false),
        ("build-dependencies", "dependencies", false),
        ("lints", "lints", true),
    ] {
        if let Some((cargo_toml, root)) = cargo_toml.get_mut(key).zip(w.get(ws_key)) {
            if inherit {
                try_inherit_cargo_table(cargo_toml, root);
            } else {
                try_merge_cargo_tables(cargo_toml, root);
            }
        };

        if let Some(targets) = cargo_toml.get_mut("target").and_then(try_as_table_like_mut) {
            for (_, tp) in targets.iter_mut() {
                if let Some((cargo_toml, root)) = tp.get_mut(key).zip(w.get(ws_key)) {
                    if inherit {
                        try_inherit_cargo_table(cargo_toml, root);
                    } else {
                        try_merge_cargo_tables(cargo_toml, root);
                    }
                }
            }
        }
    }
}

/// Return a [`toml_edit::TableLike`] representation of the [`Item`] (if any)
fn try_as_table_like(item: &Item) -> Option<&dyn toml_edit::TableLike> {
    match item {
        Item::Table(w) => Some(w),
        Item::Value(toml_edit::Value::InlineTable(w)) => Some(w),
        _ => None,
    }
}

/// Return a mutable [`toml_edit::TableLike`] representation of the [`Item`] (if any)
fn try_as_table_like_mut(item: &mut Item) -> Option<&mut dyn toml_edit::TableLike> {
    match item {
        Item::Table(w) => Some(w),
        Item::Value(toml_edit::Value::InlineTable(w)) => Some(w),
        _ => None,
    }
}

/// Inherit the specified `cargo_toml` from workspace `root` if the former is a table
fn try_inherit_cargo_table(cargo_toml: &mut Item, root: &Item) {
    let Some(t) = try_as_table_like_mut(cargo_toml) else {
        return;
    };
    if t.get("workspace")
        .and_then(Item::as_bool)
        .unwrap_or_default()
    {
        t.remove("workspace");
        let orig_val = mem::replace(cargo_toml, root.clone());
        merge_items(cargo_toml, orig_val);
    }
}

/// Merge the specified `cargo_toml` and workspace `root` if both are tables
fn try_merge_cargo_tables(cargo_toml: &mut Item, root: &Item) {
    let cargo_toml = try_as_table_like_mut(cargo_toml);
    let root = try_as_table_like(root);

    if let Some((cargo_toml, root)) = cargo_toml.zip(root) {
        merge_cargo_tables(cargo_toml, root);
    }
}
/// Merge the specified `cargo_toml` and workspace `root` tables
fn merge_cargo_tables<T, U>(cargo_toml: &mut T, root: &U)
where
    T: toml_edit::TableLike + ?Sized,
    U: toml_edit::TableLike + ?Sized,
{
    cargo_toml.iter_mut().for_each(|(k, v)| {
        // Bail if:
        // - cargo_toml isn't a table (otherwise `workspace = true` can't show up
        // - the workspace root doesn't have this key
        let (t, root_val) = match try_as_table_like_mut(&mut *v).zip(root.get(&k)) {
            Some((t, root_val)) => (t, root_val),
            _ => return,
        };

        if let Some(Item::Value(toml_edit::Value::Boolean(bool_value))) = t.get("workspace") {
            if *bool_value.value() {
                t.remove("workspace");
                let orig_val = mem::replace(v, root_val.clone());
                merge_items(v, orig_val);
            }
        }
    });
}

/// Recursively merge the `additional` item into the specified `dest`
fn merge_items(dest: &mut Item, additional: Item) {
    use toml_edit::Value;

    match additional {
        Item::Value(additional) => match additional {
            Value::String(_)
            | Value::Integer(_)
            | Value::Float(_)
            | Value::Boolean(_)
            | Value::Datetime(_) => {
                // Override dest completely for raw values
                *dest = Item::Value(additional);
            }

            Value::Array(additional) => {
                if let Item::Value(Value::Array(dest)) = dest {
                    dest.extend(additional);
                } else {
                    // Override dest completely if types don't match
                    *dest = Item::Value(Value::Array(additional));
                }
            }

            Value::InlineTable(additional) => {
                merge_tables(dest, additional);
            }
        },
        Item::Table(additional) => {
            merge_tables(dest, additional);
        }
        Item::None => {}
        Item::ArrayOfTables(additional) => {
            if let Item::ArrayOfTables(dest) = dest {
                dest.extend(additional);
            } else {
                // Override dest completely if types don't match
                *dest = Item::ArrayOfTables(additional);
            }
        }
    }
}

use table_like_ext::merge_tables;
mod table_like_ext {
    //! Helper functions to merge values in any combination of the two [`TableLike`] items
    //! found in [`toml_edit`]

    use toml_edit::{Item, TableLike};

    /// Recursively merge the `additional` table into `dest` (overwriting if `dest` is not a table)
    pub(super) fn merge_tables<T>(dest: &mut Item, additional: T)
    where
        T: TableLikeExt,
    {
        match dest {
            Item::Table(dest) => merge_table_like(dest, additional),
            Item::Value(toml_edit::Value::InlineTable(dest)) => merge_table_like(dest, additional),
            _ => {
                // Override dest completely if types don't match, but also
                // skip empty tables (i.e. if we had `key = { workspace = true }`
                if !additional.is_empty() {
                    *dest = additional.into_item();
                }
            }
        }
    }

    /// Recursively merge two tables
    fn merge_table_like<T, U>(dest: &mut T, additional: U)
    where
        T: TableLike,
        U: TableLikeExt,
    {
        additional
            .into_iter()
            .map(U::map_iter_item)
            .for_each(|(k, v)| match dest.get_mut(&k) {
                Some(existing) => super::merge_items(existing, v),
                None => {
                    dest.insert(&k, v);
                }
            });
    }

    /// Generalized form of the item yielded by [`IntoIterator`] for the two [`TableLike`] types
    /// in [`toml_edit`]
    type CommonIterItem = (toml_edit::InternalString, Item);

    /// Extension trait to iterate [`Item`]s from a [`TableLike`] item
    pub(super) trait TableLikeExt: TableLike + IntoIterator {
        /// Convert the iterator item to a common type
        fn map_iter_item(item: Self::Item) -> CommonIterItem;

        /// Convert the table into an [`Item`]
        fn into_item(self) -> Item;
    }

    impl TableLikeExt for toml_edit::Table {
        fn map_iter_item(item: Self::Item) -> CommonIterItem {
            item
        }

        fn into_item(self) -> Item {
            Item::Table(self)
        }
    }

    impl TableLikeExt for toml_edit::InlineTable {
        fn map_iter_item(item: Self::Item) -> CommonIterItem {
            let (k, v) = item;
            (k, Item::Value(v))
        }

        fn into_item(self) -> Item {
            Item::Value(toml_edit::Value::InlineTable(self))
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use std::str::FromStr;

    #[test]
    fn smoke() {
        let mut cargo_toml = toml_edit::Document::from_str(
            r#"
            [package]
            authors.workspace = true
            categories.workspace = true
            description.workspace = true
            documentation.workspace = true
            edition.workspace = true
            exclude.workspace = true
            homepage.workspace = true
            include.workspace = true
            keyword.workspace = true
            license.workspace = true
            license-file.workspace = true
            publish.workspace = true
            readme.workspace = true
            repository.workspace = true
            rust-version.workspace = true
            version.workspace = true

            [dependencies]
            # the `foo` dependency is most imporant, so it goes first
            foo.workspace = true
            bar.workspace = true
            baz.workspace = true
            qux = { workspace = true, features = ["qux-additional"] }
            corge = { workspace = true, version = "corge-vers-override" }
            grault = { version = "grault-vers" }
            garply = "garply-vers"
            waldo = "waldo-vers"

            [target.'cfg(unix)'.dependencies]
            unix = { workspace = true, features = ["some"] }

            [dev-dependencies]
            foo.workspace = true
            bar.workspace = true
            baz.workspace = true
            qux = { workspace = true, features = ["qux-additional"] }
            corge = { workspace = true, version = "corge-vers-override" }
            grault = { version = "grault-vers" }
            garply = "garply-vers"
            waldo = "waldo-vers"

            [build-dependencies]
            foo.workspace = true
            bar.workspace = true
            baz.workspace = true
            qux = { workspace = true, features = ["qux-additional"] }
            corge = { workspace = true, version = "corge-vers-override" }
            grault = { version = "grault-vers" }
            garply = "garply-vers"
            waldo = "waldo-vers"

            [features]
            # this feature is a demonstration that comments are preserved
            my_feature = []

            [lints]
            workspace = true
        "#,
        )
        .unwrap();

        let root_toml = toml_edit::Document::from_str(
            r#"
            [workspace.package]
            authors = ["first author", "second author"]
            categories = ["first category", "second category" ]
            description = "some description"
            documentation = "some doc url"
            edition = "2021"
            exclude = ["first exclusion", "second exclusion"]
            homepage = "some home page"
            include = ["first inclusion", "second inclusion"]
            keyword = ["first keyword", "second keyword"]
            license = "some license"
            license-file = "some license-file"
            publish = true
            readme = "some readme"
            repository = "some repository"
            rust-version = "some rust-version"
            version = "some version"

            [workspace.dependencies]
            # top-level workspace comments are not copied - only the values are merged
            foo = { version = "foo-vers" }
            bar = { version = "bar-vers", default-features = false }
            baz = { version = "baz-vers", features = ["baz-feat", "baz-feat2"] }
            qux = { version = "qux-vers", features = ["qux-feat"] }
            corge = { version = "corge-vers", features = ["qux-feat"] }
            garply = "garply-workspace-vers"
            waldo = { version = "waldo-workspace-vers" }
            unix = { version = "unix-vers" }

            [workspace.lints.rust]
            unused_extern_crates = 'warn'

            [workspace.lints.clippy]
            all = 'allow'
        "#,
        )
        .unwrap();

        // NOTE: The nonstandard spacing is due to reusing decorations from original keys/values
        // in cargo_toml
        let expected_toml_str = r#"
            [package]
            authors= ["first author", "second author"]
            categories= ["first category", "second category" ]
            description= "some description"
            documentation= "some doc url"
            edition= "2021"
            exclude= ["first exclusion", "second exclusion"]
            homepage= "some home page"
            include= ["first inclusion", "second inclusion"]
            keyword= ["first keyword", "second keyword"]
            license= "some license"
            license-file= "some license-file"
            publish= true
            readme= "some readme"
            repository= "some repository"
            rust-version= "some rust-version"
            version= "some version"

            [dependencies]
            # the `foo` dependency is most imporant, so it goes first
            foo= { version = "foo-vers" }
            bar= { version = "bar-vers", default-features = false }
            baz= { version = "baz-vers", features = ["baz-feat", "baz-feat2"] }
            qux = { version = "qux-vers", features = ["qux-feat","qux-additional"] }
            corge = { version = "corge-vers-override" , features = ["qux-feat"] }
            grault = { version = "grault-vers" }
            garply = "garply-vers"
            waldo = "waldo-vers"

            [target.'cfg(unix)'.dependencies]
            unix = { version = "unix-vers" , features = ["some"] }

            [lints.rust]
            unused_extern_crates = 'warn'

            [dev-dependencies]
            foo= { version = "foo-vers" }
            bar= { version = "bar-vers", default-features = false }
            baz= { version = "baz-vers", features = ["baz-feat", "baz-feat2"] }
            qux = { version = "qux-vers", features = ["qux-feat","qux-additional"] }
            corge = { version = "corge-vers-override" , features = ["qux-feat"] }
            grault = { version = "grault-vers" }
            garply = "garply-vers"
            waldo = "waldo-vers"

            [lints.clippy]
            all = 'allow'

            [build-dependencies]
            foo= { version = "foo-vers" }
            bar= { version = "bar-vers", default-features = false }
            baz= { version = "baz-vers", features = ["baz-feat", "baz-feat2"] }
            qux = { version = "qux-vers", features = ["qux-feat","qux-additional"] }
            corge = { version = "corge-vers-override" , features = ["qux-feat"] }
            grault = { version = "grault-vers" }
            garply = "garply-vers"
            waldo = "waldo-vers"

            [features]
            # this feature is a demonstration that comments are preserved
            my_feature = []
        "#;

        super::merge(&mut cargo_toml, &root_toml);

        assert_eq!(expected_toml_str, cargo_toml.to_string());
    }

    #[test]
    fn sqlx_workspace() {
        let mut cargo_toml = toml_edit::Document::from_str(
            r#"
            [package]
            name = "sqlx-mysql"
            documentation = "https://docs.rs/sqlx"
            description = "MySQL driver implementation for SQLx. Not for direct use; see the `sqlx` crate for details."
            version.workspace = true
            license.workspace = true
            edition.workspace = true
            authors.workspace = true
            repository.workspace = true
            # See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

            [features]
            json = ["sqlx-core/json", "serde"]
            any = ["sqlx-core/any"]
            offline = ["sqlx-core/offline", "serde/derive"]
            migrate = ["sqlx-core/migrate"]
            _rt-tokio = ["sqlx-core/_rt-tokio", "tokio"]

            [dependencies]
            sqlx-core = { workspace = true }

            # Support for tokio::io::AsyncWrite in mysql::infile
            tokio = { workspace = true, optional = true }

            # Futures crates
            futures-channel = { version = "0.3.19", default-features = false, features = ["sink", "alloc", "std"] }
            futures-core = { version = "0.3.19", default-features = false }
            futures-io = "0.3.24"
            futures-util = { version = "0.3.19", default-features = false, features = ["alloc", "sink", "io"] }

            # Cryptographic Primitives
            crc = "3.0.0"
            digest = { version = "0.10.0", default-features = false, features = ["std"] }
            hkdf = "0.12.0"
            hmac = { version = "0.12.0", default-features = false }
            md-5 = { version = "0.10.0", default-features = false }
            rand = { version = "0.8.4", default-features = false, features = ["std", "std_rng"] }
            rsa = "0.9"
            sha1 = { version = "0.10.1", default-features = false }
            sha2 = { version = "0.10.0", default-features = false }

            # Type Integrations (versions inherited from `[workspace.dependencies]`)
            bigdecimal = { workspace = true, optional = true }
            chrono = { workspace = true, optional = true }
            rust_decimal = { workspace = true, optional = true }
            time = { workspace = true, optional = true }
            uuid = { workspace = true, optional = true }

            # Misc
            atoi = "2.0"
            base64 = { version = "0.21.0", default-features = false, features = ["std"] }
            bitflags = { version = "2", default-features = false, features = ["serde"] }
            byteorder = { version = "1.4.3", default-features = false, features = ["std"] }
            bytes = "1.1.0"
            dotenvy = "0.15.5"
            either = "1.6.1"
            generic-array = { version = "0.14.4", default-features = false }
            hex = "0.4.3"
            itoa = "1.0.1"
            log = "0.4.17"
            memchr = { version = "2.4.1", default-features = false }
            once_cell = "1.9.0"
            percent-encoding = "2.1.0"
            smallvec = "1.7.0"
            stringprep = "0.1.2"
            thiserror = "1.0.35"
            tracing = { version = "0.1.37", features = ["log"] }
            whoami = { version = "1.2.1", default-features = false }

            serde = { version = "1.0.144", optional = true }"
            "#,
        ).unwrap();

        let root_toml = toml_edit::Document::from_str(
            r#"
            [workspace]
            members = [
                ".",
                "sqlx-core",
                "sqlx-macros",
                "sqlx-macros-core",
                "sqlx-test",
                "sqlx-cli",
            #    "sqlx-bench",
                "sqlx-mysql",
                "sqlx-postgres",
                "sqlx-sqlite",
                "examples/mysql/todos",
                "examples/postgres/axum-social-with-tests",
                "examples/postgres/chat",
                "examples/postgres/files",
                "examples/postgres/json",
                "examples/postgres/listen",
                "examples/postgres/todos",
                "examples/postgres/mockable-todos",
                "examples/postgres/transaction",
                "examples/sqlite/todos",
            ]

            [workspace.package]
            version = "0.7.3"
            license = "MIT OR Apache-2.0"
            edition = "2021"
            repository = "https://github.com/launchbadge/sqlx"
            keywords = ["database", "async", "postgres", "mysql", "sqlite"]
            categories = ["database", "asynchronous"]
            authors = [
                "Ryan Leckey <leckey.ryan@gmail.com>",
                "Austin Bonander <austin.bonander@gmail.com>",
                "Chloe Ross <orangesnowfox@gmail.com>",
                "Daniel Akhterov <akhterovd@gmail.com>",
            ]

            [package]
            name = "sqlx"
            readme = "README.md"
            documentation = "https://docs.rs/sqlx"
            description = "🧰 The Rust SQL Toolkit. An async, pure Rust SQL crate featuring compile-time checked queries without a DSL. Supports PostgreSQL, MySQL, and SQLite."
            version.workspace = true
            license.workspace = true
            edition.workspace = true
            authors.workspace = true
            repository.workspace = true

            [package.metadata.docs.rs]
            features = ["all-databases", "_unstable-all-types"]
            rustdoc-args = ["--cfg", "docsrs"]

            [features]
            default = ["any", "macros", "migrate", "json"]
            macros = ["sqlx-macros"]
            migrate = ["sqlx-core/migrate", "sqlx-macros?/migrate", "sqlx-mysql?/migrate", "sqlx-postgres?/migrate", "sqlx-sqlite?/migrate"]

            # intended mainly for CI and docs
            all-databases = ["mysql", "sqlite", "postgres", "any"]
            _unstable-all-types = [
                "bigdecimal",
                "rust_decimal",
                "json",
                "time",
                "chrono",
                "ipnetwork",
                "mac_address",
                "uuid",
                "bit-vec",
            ]

            # Base runtime features without TLS
            runtime-async-std = ["_rt-async-std", "sqlx-core/_rt-async-std", "sqlx-macros?/_rt-async-std"]
            runtime-tokio = ["_rt-tokio", "sqlx-core/_rt-tokio", "sqlx-mysql/_rt-tokio", "sqlx-macros?/_rt-tokio"]

            # TLS features
            tls-native-tls = ["sqlx-core/_tls-native-tls", "sqlx-macros?/_tls-native-tls"]
            tls-rustls = ["sqlx-core/_tls-rustls", "sqlx-macros?/_tls-rustls"]

            # No-op feature used by the workflows to compile without TLS enabled. Not meant for general use.
            tls-none = []

            # Legacy Runtime + TLS features

            runtime-async-std-native-tls = ["runtime-async-std", "tls-native-tls"]
            runtime-async-std-rustls = ["runtime-async-std", "tls-rustls"]

            runtime-tokio-native-tls = ["runtime-tokio", "tls-native-tls"]
            runtime-tokio-rustls = ["runtime-tokio", "tls-rustls"]

            # for conditional compilation
            _rt-async-std = []
            _rt-tokio = []

            # database
            any = ["sqlx-core/any", "sqlx-mysql?/any", "sqlx-postgres?/any", "sqlx-sqlite?/any"]
            postgres = ["sqlx-postgres", "sqlx-macros?/postgres"]
            mysql = ["sqlx-mysql", "sqlx-macros?/mysql"]
            sqlite = ["sqlx-sqlite", "sqlx-macros?/sqlite"]

            # types
            json = ["sqlx-macros?/json", "sqlx-mysql?/json", "sqlx-postgres?/json", "sqlx-sqlite?/json"]

            bigdecimal = ["sqlx-core/bigdecimal", "sqlx-macros?/bigdecimal", "sqlx-mysql?/bigdecimal", "sqlx-postgres?/bigdecimal"]
            bit-vec = ["sqlx-core/bit-vec", "sqlx-macros?/bit-vec", "sqlx-postgres?/bit-vec"]
            chrono = ["sqlx-core/chrono", "sqlx-macros?/chrono", "sqlx-mysql?/chrono", "sqlx-postgres?/chrono", "sqlx-sqlite?/chrono"]
            ipnetwork = ["sqlx-core/ipnetwork", "sqlx-macros?/ipnetwork", "sqlx-postgres?/ipnetwork"]
            mac_address = ["sqlx-core/mac_address", "sqlx-macros?/mac_address", "sqlx-postgres?/mac_address"]
            rust_decimal = ["sqlx-core/rust_decimal", "sqlx-macros?/rust_decimal", "sqlx-mysql?/rust_decimal", "sqlx-postgres?/rust_decimal"]
            time = ["sqlx-core/time", "sqlx-macros?/time", "sqlx-mysql?/time", "sqlx-postgres?/time", "sqlx-sqlite?/time"]
            uuid = ["sqlx-core/uuid", "sqlx-macros?/uuid", "sqlx-mysql?/uuid", "sqlx-postgres?/uuid", "sqlx-sqlite?/uuid"]
            regexp = ["sqlx-sqlite?/regexp"]

            [workspace.dependencies]
            # Core Crates
            sqlx-core = { version = "=0.7.3", path = "sqlx-core" }
            sqlx-macros-core = { version = "=0.7.3", path = "sqlx-macros-core" }
            sqlx-macros = { version = "=0.7.3", path = "sqlx-macros" }

            # Driver crates
            sqlx-mysql = { version = "=0.7.3", path = "sqlx-mysql" }
            sqlx-postgres = { version = "=0.7.3", path = "sqlx-postgres" }
            sqlx-sqlite = { version = "=0.7.3", path = "sqlx-sqlite" }

            # Facade crate (for reference from sqlx-cli)
            sqlx = { version = "=0.7.3", path = ".", default-features = false }

            # Common type integrations shared by multiple driver crates.
            # These are optional unless enabled in a workspace crate.
            bigdecimal = "0.3.0"
            bit-vec = "0.6.3"
            chrono = { version = "0.4.22", default-features = false }
            ipnetwork = "0.20.0"
            mac_address = "1.1.5"
            rust_decimal = "1.26.1"
            time = { version = "0.3.14", features = ["formatting", "parsing", "macros"] }
            uuid = "1.1.2"

            # Common utility crates
            dotenvy = { version = "0.15.0", default-features = false }

            # Runtimes
            [workspace.dependencies.async-std]
            version = "1.12"

            [workspace.dependencies.tokio]
            version = "1"
            features = ["time", "net", "sync", "fs", "io-util", "rt"]
            default-features = false

            [dependencies]
            sqlx-core = { workspace = true, features = ["offline", "migrate"] }
            sqlx-macros = { workspace = true, optional = true }

            sqlx-mysql = { workspace = true, optional = true }
            sqlx-postgres = { workspace = true, optional = true }
            sqlx-sqlite = { workspace = true, optional = true }

            [dev-dependencies]
            anyhow = "1.0.52"
            time_ = { version = "0.3.2", package = "time" }
            futures = "0.3.19"
            env_logger = "0.11"
            async-std = { version = "1.12.0", features = ["attributes"] }
            tokio = { version = "1.15.0", features = ["full"] }
            dotenvy = "0.15.0"
            trybuild = "1.0.53"
            sqlx-test = { path = "./sqlx-test" }
            paste = "1.0.6"
            serde = { version = "1.0.132", features = ["derive"] }
            serde_json = "1.0.73"
            url = "2.2.2"
            rand = "0.8.4"
            rand_xoshiro = "0.6.0"
            hex = "0.4.3"
            tempfile = "3.9.0"
            criterion = { version = "0.5.1", features = ["async_tokio"] }

            # Needed to test SQLCipher
            libsqlite3-sys = { version = "0.27", features = ["bundled-sqlcipher"] }

            #
            # Any
            #

            [[test]]
            name = "any"
            path = "tests/any/any.rs"
            required-features = ["any"]

            [[test]]
            name = "any-pool"
            path = "tests/any/pool.rs"
            required-features = ["any"]

            #
            # Migrations
            #

            [[test]]
            name = "migrate-macro"
            path = "tests/migrate/macro.rs"
            required-features = ["macros", "migrate"]

            #
            # SQLite
            #

            [[test]]
            name = "sqlite"
            path = "tests/sqlite/sqlite.rs"
            required-features = ["sqlite"]

            [[test]]
            name = "sqlite-any"
            path = "tests/sqlite/any.rs"
            required-features = ["sqlite"]

            [[test]]
            name = "sqlite-types"
            path = "tests/sqlite/types.rs"
            required-features = ["sqlite"]

            [[test]]
            name = "sqlite-describe"
            path = "tests/sqlite/describe.rs"
            required-features = ["sqlite"]

            [[test]]
            name = "sqlite-macros"
            path = "tests/sqlite/macros.rs"
            required-features = ["sqlite", "macros"]

            [[test]]
            name = "sqlite-derives"
            path = "tests/sqlite/derives.rs"
            required-features = ["sqlite", "macros"]

            [[test]]
            name = "sqlite-error"
            path = "tests/sqlite/error.rs"
            required-features = ["sqlite"]

            [[test]]
            name = "sqlite-sqlcipher"
            path = "tests/sqlite/sqlcipher.rs"
            required-features = ["sqlite"]

            [[test]]
            name = "sqlite-test-attr"
            path = "tests/sqlite/test-attr.rs"
            required-features = ["sqlite", "macros", "migrate"]

            [[test]]
            name = "sqlite-migrate"
            path = "tests/sqlite/migrate.rs"
            required-features = ["sqlite", "macros", "migrate"]

            [[bench]]
            name = "sqlite-describe"
            path = "benches/sqlite/describe.rs"
            harness = false
            required-features = ["sqlite"]

            #
            # MySQL
            #

            [[test]]
            name = "mysql"
            path = "tests/mysql/mysql.rs"
            required-features = ["mysql"]

            [[test]]
            name = "mysql-types"
            path = "tests/mysql/types.rs"
            required-features = ["mysql"]

            [[test]]
            name = "mysql-describe"
            path = "tests/mysql/describe.rs"
            required-features = ["mysql"]

            [[test]]
            name = "mysql-macros"
            path = "tests/mysql/macros.rs"
            required-features = ["mysql", "macros"]

            [[test]]
            name = "mysql-error"
            path = "tests/mysql/error.rs"
            required-features = ["mysql"]

            [[test]]
            name = "mysql-test-attr"
            path = "tests/mysql/test-attr.rs"
            required-features = ["mysql", "macros", "migrate"]

            [[test]]
            name = "mysql-migrate"
            path = "tests/mysql/migrate.rs"
            required-features = ["mysql", "macros", "migrate"]

            #
            # PostgreSQL
            #

            [[test]]
            name = "postgres"
            path = "tests/postgres/postgres.rs"
            required-features = ["postgres"]

            [[test]]
            name = "postgres-types"
            path = "tests/postgres/types.rs"
            required-features = ["postgres"]

            [[test]]
            name = "postgres-describe"
            path = "tests/postgres/describe.rs"
            required-features = ["postgres"]

            [[test]]
            name = "postgres-macros"
            path = "tests/postgres/macros.rs"
            required-features = ["postgres", "macros"]

            [[test]]
            name = "postgres-derives"
            path = "tests/postgres/derives.rs"
            required-features = ["postgres", "macros"]

            [[test]]
            name = "postgres-error"
            path = "tests/postgres/error.rs"
            required-features = ["postgres"]

            [[test]]
            name = "postgres-test-attr"
            path = "tests/postgres/test-attr.rs"
            required-features = ["postgres", "macros", "migrate"]

            [[test]]
            name = "postgres-migrate"
            path = "tests/postgres/migrate.rs"
            required-features = ["postgres", "macros", "migrate"]
        "#).unwrap();

        let expected_toml_str = r#"
            [package]
            name = "sqlx-mysql"
            documentation = "https://docs.rs/sqlx"
            description = "MySQL driver implementation for SQLx. Not for direct use; see the `sqlx` crate for details."
            version.workspace = true
            license.workspace = true
            edition.workspace = true
            authors.workspace = true
            repository.workspace = true
            # See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

            [features]
            json = ["sqlx-core/json", "serde"]
            any = ["sqlx-core/any"]
            offline = ["sqlx-core/offline", "serde/derive"]
            migrate = ["sqlx-core/migrate"]
            _rt-tokio = ["sqlx-core/_rt-tokio", "tokio"]

            [dependencies]
            sqlx-core = { version = "=0.7.3", path = "sqlx-core" }

            # Support for tokio::io::AsyncWrite in mysql::infile
            tokio = { workspace = true, optional = true }

            # Futures crates
            futures-channel = { version = "0.3.19", default-features = false, features = ["sink", "alloc", "std"] }
            futures-core = { version = "0.3.19", default-features = false }
            futures-io = "0.3.24"
            futures-util = { version = "0.3.19", default-features = false, features = ["alloc", "sink", "io"] }

            # Cryptographic Primitives
            crc = "3.0.0"
            digest = { version = "0.10.0", default-features = false, features = ["std"] }
            hkdf = "0.12.0"
            hmac = { version = "0.12.0", default-features = false }
            md-5 = { version = "0.10.0", default-features = false }
            rand = { version = "0.8.4", default-features = false, features = ["std", "std_rng"] }
            rsa = "0.9"
            sha1 = { version = "0.10.1", default-features = false }
            sha2 = { version = "0.10.0", default-features = false }

            # Type Integrations (versions inherited from `[workspace.dependencies]`)
            bigdecimal = { version = "0.3.0", optional = true }
            chrono = { version = "0.4.22", default-features = false , optional = true }
            rust_decimal = { version = "1.26.1", optional = true }
            time = { version = "0.3.14", features = ["formatting", "parsing", "macros"] , optional = true }
            uuid = { version = "1.1.2", optional = true }

            # Misc
            atoi = "2.0"
            base64 = { version = "0.21.0", default-features = false, features = ["std"] }
            bitflags = { version = "2", default-features = false, features = ["serde"] }
            byteorder = { version = "1.4.3", default-features = false, features = ["std"] }
            bytes = "1.1.0"
            dotenvy = "0.15.5"
            either = "1.6.1"
            generic-array = { version = "0.14.4", default-features = false }
            hex = "0.4.3"
            itoa = "1.0.1"
            log = "0.4.17"
            memchr = { version = "2.4.1", default-features = false }
            once_cell = "1.9.0"
            percent-encoding = "2.1.0"
            smallvec = "1.7.0"
            stringprep = "0.1.2"
            thiserror = "1.0.35"
            tracing = { version = "0.1.37", features = ["log"] }
            whoami = { version = "1.2.1", default-features = false }

            serde = { version = "1.0.144", optional = true }


            [dependencies.tokio]
            # Support for tokio::io::AsyncWrite in mysql::infile
            version = "1"
            features = ["time", "net", "sync", "fs", "io-util", "rt"]
            default-features = false
            optional = true
        "#;

        super::merge(&mut cargo_toml, &root_toml);

        assert_eq!(expected_toml_str, cargo_toml.to_string());
    }
}
