//! In-kernel unit tests (feature `ktest`, SPEC §B10).
//!
//! `ktest!` places a [`KTest`] entry for each test in the `.ktest_array` link section (stable
//! Rust has no custom test frameworks). After boot, [`run_all`] runs every entry, prints one
//! line per test and a `KTEST SUMMARY` line, and exits QEMU through semihosting with status
//! 0 only if every test passed. `scripts/ktest.sh` checks both the status and the summary.
//!
//! A test body is a block of type `()`; the assertion macros print the failure and return.

use crate::arch::semihosting;

pub struct KTest {
    pub name: &'static str,
    pub run: fn() -> TestResult,
}

pub type TestResult = Result<(), Failure>;

/// The failure details are printed where the assertion fails.
pub struct Failure;

macro_rules! ktest {
    ($(fn $name:ident() $body:block)*) => {
        $(
            fn $name() -> $crate::ktest::TestResult {
                let () = $body;
                Ok(())
            }

            const _: () = {
                #[used]
                #[unsafe(link_section = ".ktest_array")]
                static TEST: $crate::ktest::KTest = $crate::ktest::KTest {
                    name: concat!(module_path!(), "::", stringify!($name)),
                    run: $name,
                };
            };
        )*
    };
}

macro_rules! kfail {
    ($($arg:tt)+) => {{
        kprintln!("    failed at {}:{}: {}", file!(), line!(), format_args!($($arg)+));
        return Err($crate::ktest::Failure);
    }};
}

macro_rules! kassert {
    ($cond:expr $(,)?) => {
        if !$cond {
            kfail!("{}", stringify!($cond));
        }
    };
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            kfail!($($arg)+);
        }
    };
}

macro_rules! kassert_eq {
    ($left:expr, $right:expr $(,)?) => {
        kassert_eq!($left, $right, "{} == {}", stringify!($left), stringify!($right))
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        match (&$left, &$right) {
            (left, right) => {
                if *left != *right {
                    kfail!("{}\n      left: {:?}\n     right: {:?}", format_args!($($arg)+), left, right);
                }
            }
        }
    };
}

/// The `Ok` value of a `Result`, or a test failure showing the error.
macro_rules! kunwrap {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => kfail!("{} returned Err({:?})", stringify!($result), e),
        }
    };
}

/// The `Err` value of a `Result`, or a test failure showing the unexpected `Ok`.
macro_rules! kunwrap_err {
    ($result:expr) => {
        match $result {
            Err(e) => e,
            Ok(value) => kfail!("{} unexpectedly returned Ok({:?})", stringify!($result), value),
        }
    };
}

fn registered() -> &'static [KTest] {
    unsafe extern "C" {
        static __ktest_start: u8;
        static __ktest_end: u8;
    }
    let start = (&raw const __ktest_start).cast::<KTest>();
    let bytes = &raw const __ktest_end as usize - start as usize;
    assert!(bytes.is_multiple_of(size_of::<KTest>()), ".ktest_array is not an array of KTest");
    // SAFETY: the linker script places all `KTest` statics emitted by `ktest!`, and nothing
    // else, contiguously between these two symbols.
    unsafe { core::slice::from_raw_parts(start, bytes / size_of::<KTest>()) }
}

pub fn run_all() -> ! {
    let tests = registered();
    kprintln!("KTEST START count={}", tests.len());
    let mut failed = 0;
    for test in tests {
        match (test.run)() {
            Ok(()) => kprintln!("[ok]   {}", test.name),
            Err(Failure) => {
                failed += 1;
                kprintln!("[FAIL] {}", test.name);
            }
        }
    }
    // Last: it hands all remaining memory to the root task, so nothing can allocate after.
    let name = "aos_kernel::user_tests::root_task_distributes_and_exits";
    match crate::user_tests::root_task_distributes_and_exits() {
        Ok(()) => kprintln!("[ok]   {name}"),
        Err(Failure) => {
            failed += 1;
            kprintln!("[FAIL] {name}");
        }
    }
    let passed = tests.len() + 1 - failed;
    kprintln!("KTEST SUMMARY passed={} failed={}", passed, failed);
    semihosting::exit(if failed == 0 && passed > 0 { 0 } else { 1 })
}
