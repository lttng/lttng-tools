#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
# SPDX-License-Identifier: GPL-2.0-only
#
"""
Validate that lttng-crash doesn't read out of bounds while
parsing files that look like ringbuffers.
"""

import copy
import logging
import pathlib
import sys
import subprocess
from typing import Any, Dict, List, Optional

# Import in-tree test utils
# Modify this depending on where the test file is in the tree
test_utils_import_path = pathlib.Path(__file__).absolute().parents[3] / "utils"
sys.path.insert(0, str(test_utils_import_path))

import lttngtest


normand_import_path = (
    pathlib.Path(__file__).absolute().parents[3] / "vendor" / "normand"
)
sys.path.insert(0, str(normand_import_path))

import normand


def get_abi_str(major: int, minor: int) -> str:
    test_dir = pathlib.Path(__file__).parents[0]
    abi_str = ""
    with open(str(test_dir / "abi_unknown.normand"), "r") as f:
        abi_str = f.read() + "\n"

    if major in [0, 1] and minor == 0:
        with open(str(test_dir / "abi_0_0.normand"), "r") as f:
            abi_str += f.read()

    with open(str(test_dir / "ringbuffer_data.normand"), "r") as f:
        abi_str += f.read()

    return abi_str


class Vars(dict):
    def __init__(self, changes: Optional[Dict[str, Any]] = None):
        self.update(
            {
                "magic": [
                    0x17,
                    0x7B,
                    0xF1,
                    0x77,
                    0xBF,
                    0x17,
                    0x7B,
                    0xF1,
                    0x77,
                    0xBF,
                    0x17,
                    0x7B,
                    0xF1,
                    0x77,
                    0xBF,
                    0x17,
                ],
                # When this is None, normand will use the offset of the _end label
                "mmap_length": None,
                "endian": 0x1234,
                # Default ABI: 1_0
                "major": 1,
                "minor": 0,
                "word_size": 8,  # or 4
                "layout_type": 0,
                #
                # ABI 0_0 and 1_0
                #
                # Offset
                "prod_offset": 0,
                "consumed_offset": 0,
                "commit_hot_array": None,  # let normand decide an offset by default
                "commit_hot_seq": 0,
                "buf_wsb_array": None,
                "buf_wsb_id": 0,
                "sb_array": None,
                "sb_array_shmp_offset": 0,
                "sb_backend_p_offset": 0,
                "content_size": 0,
                "packet_size": 0,
                # Length - platform dependant, on 64-bit platforms this 8 bytes.
                "length_prod_offset": 8,
                "length_consumed_offset": 8,
                "length_commit_hot_seq": 8,
                "length_buf_wsb_id": 8,
                "length_sb_array_shmp_offset": 8,
                "length_sb_backend_p_offset": 8,
                "length_content_size": 8,
                "length_packet_size": 8,
                # Strides must be non-zero now
                "stride_commit_hot_array": 1,
                "stride_buf_wsb_array": 1,
                "stride_sb_array": 1,
                # Misc
                # Provide a valid geometry by default
                # buf_size == subbuf_size * num_subbuf
                # subbuf_size & num_subbuf must be powers of 2
                "buf_size": 1024,
                "subbuf_size": 256,
                "num_subbuf": 4,
                "mode": 0,
                #
                # Internal variables for testing only, not part of the ABI
                #
                "buf_wsb_array_data": "",
                "commit_hot_array_data": "",
                "sb_array_data": "",
                "consumed": 0,
                "produced": 0,
                "backend_page_data": "",
                # Indexed by integer offset starting at 0
                "ringbuffer_data": dict(),
            }
        )
        if changes is not None:
            self.update(changes)


class Case:
    def __init__(
        self,
        description: str,
        changes: Optional[Dict[str, Any]] = None,
        truncate_to: Optional[int] = None,
        expected_returncode: int = 0,
        expected_output_files: List[str] = ["metadata"],
    ):
        self.description = description
        self.changes = changes
        self.truncate_to = truncate_to
        self.expected_returncode = expected_returncode
        self.expected_output_files = expected_output_files

    def setup(self, input_dir: pathlib.Path, output_dir: pathlib.Path):
        abi_vars = Vars(self.changes)
        abi_str = "!le\n" + get_abi_str(abi_vars["major"], abi_vars["minor"])

        input_dir.mkdir()
        assert not output_dir.is_dir(), "output directory '{}' should not exist".format(
            output_dir
        )

        # A metadata file must be present in the input_dir.
        # The metadata file is copied as is.
        metadata_file = input_dir / "metadata"
        data_file = input_dir / "data"
        with open(str(metadata_file), "wb") as f:
            # In lttng-tools <= 2.16, the file must be at least 32 bytes
            # or lttng-crash will always exit with non-zero exit code
            f.truncate(32)

        logging.debug(abi_str)
        logging.debug(abi_vars)
        try:
            data = normand.parse(abi_str, init_variables=abi_vars)
        except normand.ParseError as e:
            for msg in e.messages:
                # Sadly, the line_no in text_location doesn't seem to line up with the abi_str, but
                # this is better than the default message without the location.
                logging.error("{} at {}".format(msg.text, msg.text_location))
            raise

        logging.debug("Data:\n{}".format(data.data))
        logging.info("Data length: {}".format(len(data.data)))

        with open(str(data_file), "wb") as f:
            f.write(data.data)
            if self.truncate_to is not None:
                logging.info(
                    "{} data file to {} bytes".format(
                        (
                            "Truncating"
                            if self.truncate_to < len(data.data)
                            else "Padding"
                        ),
                        self.truncate_to,
                    )
                )
                f.truncate(self.truncate_to)


def test(
    tap: lttngtest.TapGenerator,
    test_env: lttngtest._Environment,
    test_case: Case,
) -> None:
    test_temp_dir = lttngtest.environment.TemporaryDirectory("test")
    input_dir = test_temp_dir.path / "input"
    output_dir = test_temp_dir.path / "output"
    test_case.setup(input_dir, output_dir)

    args = [
        str(test_env.default_profile().lttng_crash_path),
        "-v",
        "-x",
        str(output_dir),
        str(input_dir),
    ]
    logging.info("Running command: {}".format(" ".join(args)))
    p = subprocess.Popen(args)
    p.wait()
    logging.info("Process return code: {}".format(p.returncode))

    # Validate the output directory contains the expected files and no others
    children = list()
    for child in output_dir.iterdir():
        children.append(str(child.relative_to(output_dir)))

    missing_files = set(test_case.expected_output_files) - set(children)
    assert (
        len(missing_files) == 0
    ), "The following expected output files are missing: {}".format(missing_files)

    extra_files = set(children) - set(test_case.expected_output_files)
    assert (
        len(extra_files) == 0
    ), "The following output files are unexpected: {}".format(extra_files)

    # When a subprocess exists due a to a signal, Python sets the returncode
    # to the signal number and sets the highest bit (to make it negative), e.g.
    #  -6: ABRT
    #  -8: SIGFPE
    # -11: SIGSEGV
    assert (
        p.returncode == test_case.expected_returncode
    ), "Returncode {} doesn't match expectation: {}".format(
        p.returncode, test_case.expected_returncode
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=lttngtest.utils.get_logging_format())
    tests = [
        Case("Default test buffer is valid"),
        Case("Small files cause an error", truncate_to=31, expected_returncode=1),
        Case("Modules layout_type is skipped", changes={"layout_type": 1}),
        Case(
            "Unknown ABI major version causes an error",
            changes={"major": -1},
            expected_returncode=1,
        ),
        Case("Unknown layout_type is skipped", changes={"layout_type": -1}),
        Case("Invalid magic is skipped", changes={"magic": [x for x in range(16)]}),
        Case("Unknown endianness is skipped", changes={"endian": -1}),
        Case(
            "Zero-length mmap causes an error",
            changes={"mmap_length": 0},
            expected_returncode=1,
        ),
        Case(
            "Mmap larger than file causes an error",
            truncate_to=2048,
            changes={"mmap_length": 65536},
            expected_returncode=1,
        ),
        Case("Mmap smaller than file is OK", truncate_to=65536),
    ]

    produced_more_than_consumed = {
        "produced": 555,
        "consumed": 140,
        # Auto-calculate in normand
        "prod_offset": None,
        "consumed_offset": None,
        "commit_hot_array_data": "\x08",
    }
    per_abi_tests = [
        Case(
            "Unsupported layout minor version",
            changes={
                "minor": -1,
            },
            expected_returncode=1,
        ),
        # Use zeros to catch divide-by zero
        Case(
            "Zero subbuf size",
            changes={**produced_more_than_consumed, **{"subbuf_size": 0}},
            expected_returncode=1,
        ),
        Case(
            "Zero num_subbuf",
            changes={**produced_more_than_consumed, **{"num_subbuf": 0}},
            expected_returncode=1,
        ),
    ]

    for attr in [
        "prod_offset",
        "consumed_offset",
    ]:
        per_abi_tests.extend(
            [
                Case(
                    "Read attribute size '{}' zero-length".format(attr),
                    changes={"length_{}".format(attr): 0},
                    expected_returncode=1,
                ),
                Case(
                    "Read attribute '{}' out of bounds".format(attr),
                    changes={attr: 101010102},
                    expected_returncode=1,
                ),
            ]
        )

    for attr in [
        "commit_hot_array",
        "buf_wsb_array",
        "sb_array",
    ]:
        per_abi_tests.append(
            Case(
                "Array attribute '{}' out of bounds".format(attr),
                changes={**produced_more_than_consumed, **{attr: 101010101}},
                expected_returncode=1,
            )
        )

    # These aren't covered in the above array iteration since they require individual changes.
    per_abi_tests.append(
        Case(
            "Array attribute 'commit_hot_array' stride out of bounds",
            changes={
                **produced_more_than_consumed,
                **{
                    # For the writer_subbuf_index to be >= 1 so the stride calculation isn't multiplied by 0
                    "consumed": 280,
                    "stride_commit_hot_array": 1010101010,
                },
            },
            expected_returncode=1,
        )
    )

    per_abi_tests.append(
        Case(
            "Array attribute 'buf_wsb_array' stride out of bounds",
            changes={
                **produced_more_than_consumed,
                **{
                    # For the writer_subbuf_index to be >= 1 so the stride calculation isn't multiplied by 0
                    "consumed": 280,
                    # The commit seq must be > 0.
                    "commit_hot_array_data": "\x00\x01",
                    "stride_buf_wsb_array": 1010101010,
                },
            },
            expected_returncode=1,
        )
    )

    per_abi_tests.append(
        Case(
            "Array attribute 'sb_array' stride out of bounds",
            changes={
                **produced_more_than_consumed,
                **{
                    "consumed": 280,
                    # The commit seq must be > 0.
                    "commit_hot_array_data": "\x00\x01",
                    # Set the data so that the backend_subbuf_index is 1
                    "buf_wsb_array_data": "\x00\x01",
                    "stride_sb_array": 1010101010,
                },
            },
            expected_returncode=1,
        )
    )

    # Control the contents of the the buf_wsb_array
    produced_more_than_consumed_with_array_data = {
        **produced_more_than_consumed,
        **{
            # The commit_seq must be > 0, otherwise the the sub-buffer is considered empty
            "commit_hot_array_data": "\x00\x01\x00\x00",
        },
    }
    for attr in [
        "commit_hot_seq",
        "buf_wsb_id",
        "sb_array_shmp_offset",
        "sb_backend_p_offset",
    ]:
        per_abi_tests.extend(
            [
                Case(
                    "Read attribute size '{}' zero-length".format(attr),
                    changes={
                        **produced_more_than_consumed_with_array_data,
                        **{"length_{}".format(attr): 0},
                    },
                    expected_returncode=1,
                ),
                Case(
                    "Read attribute '{}' out of bounds".format(attr),
                    changes={
                        **produced_more_than_consumed_with_array_data,
                        **{attr: 101010102},
                    },
                    expected_returncode=1,
                ),
            ]
        )

    # These attributes are considered late in processing a lot has to go OK to get there,
    # so more specific setups are required.
    #
    # There are two main axes: when the content requires patching (seq_cc != subbuf_size),
    # and when the subbuffer is already fully committed.
    no_patch_configuration = {
        **produced_more_than_consumed_with_array_data,
        **{
            # Don't run over multiple sub-buffers, just check subbuffer 0
            "produced": 255,
            # This is set to the subbuf size (256) so that the packet_size field is read
            "commit_hot_array_data": "\x00\x01",
            # This data is used to find the index of the sb_array from the start of the file
            "buf_wsb_array_data": "\x00\x00",
            # !le [512:32] -> at _backend_pages
            "sb_array_data": "\x00\x02",
            "backend_page_data": "\x00\x04",
            # Set the data for subbuffer 0 to `[p_offset]` (offset of the
            # start of the subbuffer data including headers from the start
            # of the file).
            "ringbuffer_data": {
                0: "\x00\x04",
            },
        },
    }

    patch_configuration = {
        **no_patch_configuration,
        **{
            "commit_hot_array_data": "\x0f\x00",
        },
    }

    for attr in [
        "content_size",
        "packet_size",
    ]:
        per_abi_tests.extend(
            [
                # zero-length attributes for content_size and packet_size are checked here in case lttng-crash
                # doesn't handle them properly as unset
                Case(
                    "Read attribute '{}' size zero-length".format(attr),
                    changes={
                        **(
                            patch_configuration
                            if attr == "content_size"
                            else no_patch_configuration
                        ),
                        **{
                            "length_{}".format(attr): 0,
                        },
                    },
                    expected_returncode=0,
                    expected_output_files=["metadata", "data"],
                ),
                Case(
                    "Read attribute '{}' out of bounds".format(attr),
                    changes={
                        **(
                            patch_configuration
                            if attr == "content_size"
                            else no_patch_configuration
                        ),
                        **{attr: 101010101},
                    },
                    expected_returncode=1,
                ),
            ]
        )

    per_abi_tests.append(
        Case(
            # This is useful to check since a large packet size could be an out of bounds read
            # on a memory mapped file.
            "Ring-buffer packet size is larger than sub-buffer size fails",
            changes={
                **no_patch_configuration,
                **{
                    "packet_size": 8,
                    "ringbuffer_data": {
                        # (p_offset) + (packet_size_in_bytes * CHAR_BIT)
                        0: ("\x00\x04" + "\x00" * 6)
                        + ("\x00\x0f")
                    },
                },
            },
            expected_returncode=1,
        )
    )

    for per_abi_test_case in per_abi_tests:
        for major, minor in [
            (0, 0),
            (1, 0),
        ]:
            test_case = copy.deepcopy(per_abi_test_case)
            # Update the major, minor, and description
            test_case.description = "[ABI {}_{}] {}".format(
                major, minor, test_case.description
            )
            if "major" not in test_case.changes:
                test_case.changes["major"] = major

            if "minor" not in test_case.changes:
                test_case.changes["minor"] = minor

            tests.append(test_case)

    tap = lttngtest.TapGenerator(len(tests))
    for idx, test_case in enumerate(tests):
        with tap.case(test_case.description):
            try:
                with lttngtest.test_environment(
                    with_sessiond=False, log=tap.diagnostic
                ) as test_env:
                    logging.info(
                        "Starting test {}/{} - {}".format(
                            idx + 1, len(tests), test_case.description
                        )
                    )
                    test(tap, test_env, test_case)
            except Exception as e:
                logging.exception("Unhandled exception")
                raise e

    sys.exit(0 if tap.is_successful else 1)
