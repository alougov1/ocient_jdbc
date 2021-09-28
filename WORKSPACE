workspace(name = "ocient_jdbc")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "com_google_protobuf",
    sha256 = "d0f5f605d0d656007ce6c8b5a82df3037e1d8fe8b121ed42e536f569dec16113",
    strip_prefix = "protobuf-3.14.0",
    urls = ["http://cos.corp.ocient.com/webdav/toolchain/packages/ext/protobuf-3.14.0.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

toolchain_location = "http://cos.corp.ocient.com/webdav/toolchain/packages/toolchain/"

###########################################
# ASCIIDOCTOR
###########################################

http_archive(
    name = "ruby_install_archive",
    build_file_content = """filegroup(name = "Makefile", srcs = ["Makefile"], visibility = ["//visibility:public"])""",
    patch_args = ["-p0"],
    sha256 = "d96fce7a4df70ca7a367400fbe035ff5b518408fc55924966743abf66ead7771",
    strip_prefix = "ruby-install-0.8.1",
    urls = [toolchain_location + "ruby-install-0.8.1.tar.gz"],
    workspace_file_content = "",
)

load("//bazel/external:ruby_install.bzl", "gem_install", "ruby_install", "ruby_script_install")

ruby_script_install(name = "ruby_script_install")

ruby_install(
    name = "ruby_install",
    version = "2.7.2",
)

gem_install(
    name = "ruby_gems",
    gem_failure_warning = """\033[0;31mIf you are seeing an error like the following:\033[0m
\033[94mimage.c:3:10: fatal error: wand/magick_wand.h: No such file or directory
 #include <wand/magick_wand.h>\033[0m

\033[0;31mRun 'apt install graphicsmagick-libmagick-dev-compat'\033[0m""",
    gems = [
        "asciidoctor-pdf",
        "asciidoctor",
        "prawn-gmagick",
    ],
)