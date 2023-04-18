#!/usr/bin/env python3

from aetheris import Aetheris
import endesive




def fuzz_test_verify(input_data):
    # Call the verify function with the input data
    try:
        endesive.verify(input_data)
    except Exception as e:
        print(f"Exception occurred: {str(e)}")

# Initialize the fuzzer
aetheris = Aetheris()

# Set the function to be fuzzed and the input type
aetheris.set_fuzz_function(fuzz_test_verify)
aetheris.set_input_type(bytes)

# Run the fuzzer
aetheris.fuzz()

