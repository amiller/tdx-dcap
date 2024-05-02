import struct

class TDQuoteHeader:
    def __init__(self, data):
        self.version, self.attestation_key_type, self.tee_type, _, _, self.qe_vendor_id, self.user_data = struct.unpack(
            "<HHIHH16s20s", data[:48])

    def __str__(self):
        return f"Version: {self.version}\n" \
               f"Attestation Key Type: {self.attestation_key_type}\n" \
               f"TEE Type: {hex(self.tee_type)}\n" \
               f"QE Vendor ID: {self.qe_vendor_id.hex()}\n" \
               f"User Data: {self.user_data.hex()}"

class TDQuoteBody:
    def __init__(self, data):
        offset = 0
        self.tee_tcb_svn = data[offset:offset + 16][::-1]
        offset += 16
        self.mrseam = data[offset:offset + 48][::-1]
        offset += 48
        self.mrsignerseam = data[offset:offset + 48][::-1]
        offset += 48
        self.seamattributes = data[offset:offset + 8][::-1]
        offset += 8
        self.tdattributes = int.from_bytes(data[offset:offset + 8], byteorder='little')
        offset += 8
        self.xfam = data[offset:offset + 8][::-1]
        offset += 8
        self.mrtd = data[offset:offset + 48][::-1]
        offset += 48
        self.mrconfigid = data[offset:offset + 48][::-1]
        offset += 48
        self.mrowner = data[offset:offset + 48][::-1]
        offset += 48
        self.mrownerconfig = data[offset:offset + 48][::-1]
        offset += 48
        self.rtmr0 = data[offset:offset + 48][::-1]
        offset += 48
        self.rtmr1 = data[offset:offset + 48][::-1]
        offset += 48
        self.rtmr2 = data[offset:offset + 48][::-1]
        offset += 48
        self.rtmr3 = data[offset:offset + 48][::-1]
        offset += 48
        self.reportdata = data[offset:offset + 64][::-1]

    def __str__(self):
        return f"TEE_TCB_SVN: {self.tee_tcb_svn.hex()}\n" \
               f"MRSEAM: {self.mrseam.hex()}\n" \
               f"MRSIGNERSEAM: {self.mrsignerseam.hex()}\n" \
               f"SEAMATTRIBUTES: {self.seamattributes.hex()}\n" \
               f"TDATTRIBUTES: {self.decode_tdattributes(self.tdattributes)}\n" \
               f"XFAM: {self.xfam.hex()}\n" \
               f"MRTD: {self.mrtd.hex()}\n" \
               f"MRCONFIGID: {self.mrconfigid.hex()}\n" \
               f"MROWNER: {self.mrowner.hex()}\n" \
               f"MROWNERCONFIG: {self.mrownerconfig.hex()}\n" \
               f"RTMR0: {self.rtmr0.hex()}\n" \
               f"RTMR1: {self.rtmr1.hex()}\n" \
               f"RTMR2: {self.rtmr2.hex()}\n" \
               f"RTMR3: {self.rtmr3.hex()}\n" \
               f"REPORTDATA: {self.reportdata.hex()}"

    @staticmethod
    def decode_tdattributes(tdattributes):
        tud = tdattributes & 0xFF
        debug = bool(tud & 0x1)
        tud_reserved = (tud >> 1) & 0x7F
        
        sec = (tdattributes >> 8) & 0x00FFFFFF
        sec_reserved = sec & 0x00FFFF
        sept_ve_disable = bool(sec & 0x010000)
        sec_reserved_2 = bool(sec & 0x020000)
        pks = bool(sec & 0x040000)
        kl = bool(sec & 0x080000)

        other = (tdattributes >> 32) & 0xFFFFFFFF
        other_reserved = other & 0x7FFFFFFF
        perfmon = bool(other & 0x80000000)

        return f"TUD:\n" \
               f"  DEBUG: {debug}\n" \
               f"  TUD_RESERVED: {tud_reserved:#x}\n" \
               f"SEC:\n" \
               f"  SEC_RESERVED: {sec_reserved:#x}\n" \
               f"  SEPT_VE_DISABLE: {sept_ve_disable}\n" \
               f"  SEC_RESERVED_2: {sec_reserved_2}\n" \
               f"  PKS: {pks}\n" \
               f"  KL: {kl}\n" \
               f"OTHER:\n" \
               f"  OTHER_RESERVED: {other_reserved:#x}\n" \
               f"  PERFMON: {perfmon}"

def parse_quote_file(file_path):
    with open(file_path, "rb") as f:
        header_data = f.read(48)
        header = TDQuoteHeader(header_data)
        print("Header:")
        print(header)
        print("\nBody:")
        body_data = f.read()
        body = TDQuoteBody(body_data)
        print(body)

# Example usage
if __name__ == '__main__':
    parse_quote_file("sample/quote.dat")
