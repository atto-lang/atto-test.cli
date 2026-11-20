fn main() {
    std::process::exit(oreslang_test::run(
        std::env::args_os().skip(1).collect(),
        false,
    ));
}
