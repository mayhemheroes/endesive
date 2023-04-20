#!/usr/bin/env python3

import atheris
import sys
#sys.path.append('.')

with atheris.instrument_imports():
	from endesive.pdf.fpdf import FPDF
	from PyPDF2 import PdfReader, PdfWriter




@atheris.instrument_func
def fuzz_test_verify(input_data):
    fdp = atheris.FuzzedDataProvider(input_data)
    result = fdp.ConsumeRegularFloat()
   

    # Call the verify function with the input data
    try:
        doc = FPDF()
        doc.pdf_version = "1.3"
        doc.set_compression(0)
        font = 'helvetica'
        doc.add_page()
        doc.set_font(font, '', 13.0)
        doc.cell(w=result, h=result, align='C', txt="Test", border=result, ln=2, link=None)   
        doc.output("Outputfile", "F")
        
        fname = "Outputfile"
        with open(fname, "rb") as in_file:
            input_pdf = PdfReader(in_file)
            output_pdf = PdfWriter()
            output_pdf.encrypt("1234", "1234")
            with open("Outputfile-encrypted", "wb") as out_file:        
                output_pdf.write(out_file)
            
        
    except Exception as e:
        return -1



def main():
    atheris.Setup(sys.argv, fuzz_test_verify)
    atheris.Fuzz()

if __name__ == "__main__":
    main()

