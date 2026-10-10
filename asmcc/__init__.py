__version__ = "2.0.2"
import struct
import re

class AssemblyCraftCompilerError(Exception):
    pass

class AssemblyCraftCompiler:
    MAGIC_HEADER = (b"ACX" + __version__.split(".")[0].encode())

    ALLOC_SIZES = {
        'ds': 16,
        'dm': 32,
        'db': 64
    }

    REGISTERS = {
        'rax': 0x00, 'rbx': 0x01, 'rcx': 0x02, 'rdx': 0x03,
        'rsi': 0x04, 'rdi': 0x05, 'rbp': 0x06, 'rsp': 0x07,
        'r8': 0x08,  'r9': 0x09,  'r10': 0x0A, 'r11': 0x0B,
        'r12': 0x0C, 'r13': 0x0D, 'r14': 0x0E, 'r15': 0x0F
    }

    OPCODES = {
        'mov':     0x01,
        'push':    0x02,
        'pop':     0x03,
        'call':    0x04,
        'ret':     0x05,
        'cmp':     0x06,
        'jmp':     0x07,
        'je':      0x08,
        'jne':     0x09,
        'jg':      0x0A,
        'jl':      0x0B,
        'jge':     0x0C,
        'jle':     0x0D,
        'xor':     0x0E,
        'add':     0x0F,
        'sub':     0x10,
        'mul':     0x11,
        'div':     0x12,
        'syscall': 0x13
    }

    ARG_TYPE_REG = 0x01
    ARG_TYPE_VAR = 0x02
    ARG_TYPE_IMM = 0x03

    def __init__(self):
        self.variables = {}
        self.labels = {}
        self.bytecode = bytearray()

    def compile(self, source_code: str, output_filepath: str):
        data_lines, text_lines = self._split_sections(source_code)

        if not text_lines:
            raise AssemblyCraftCompilerError("Compilation failed: Missing or empty 'section .text'.")

        self._parse_data_section(data_lines)
        self._parse_text_section(text_lines)

        binary_data = self._generate_binary()

        try:
            with open(output_filepath, "wb") as f:
                f.write(binary_data)
        except OSError as e:
            raise AssemblyCraftCompilerError(
                f"Failed to write output file '{output_filepath}': {e}"
            ) from e

    def _split_sections(self, code: str):
        current_section = None
        data_lines, text_lines = [], []

        for line_num, line in enumerate(code.splitlines(), start=1):
            line = re.sub(r';.*$', '', line).strip()
            if not line:
                continue
            if line.startswith("section .data"):
                current_section = "data"
                continue
            elif line.startswith("section .text"):
                current_section = "text"
                continue

            if current_section == "data":
                data_lines.append((line_num, line))
            elif current_section == "text":
                text_lines.append((line_num, line))
            else:
                raise AssemblyCraftCompilerError(
                    f"Line {line_num}: Statement '{line}' outside of any section "
                    f"(expected 'section .data' or 'section .text')."
                )

        return data_lines, text_lines

    def _parse_data_section(self, lines: list):
        var_id = 0
        for line_num, line in lines:
            match = re.match(r'^([a-zA-Z_]\w*)\s+(ds|dm|db)\s+(.+)$', line)
            if not match:
                raise AssemblyCraftCompilerError(
                    f"Line {line_num}: Malformed data statement '{line}'."
                )

            var_name, size_type, values_str = match.groups()

            if var_name in self.variables:
                raise AssemblyCraftCompilerError(
                    f"Line {line_num}: Duplicate variable definition '{var_name}'."
                )

            # Check if values_str is a single integer specifying buffer allocation size (e.g. 'disk_buffer dm 512')
            single_num_match = re.fullmatch(r'^(\d+|0x[0-9a-fA-F]+)$', values_str.strip())
            if single_num_match:
                val = int(single_num_match.group(1), 0)
                if size_type == 'dm' or val > 255:
                    alloc_len = val
                    padded_data = bytes(alloc_len)
                    self.variables[var_name] = {
                        'id': var_id,
                        'size_type': size_type,
                        'alloc_len': alloc_len,
                        'data': padded_data
                    }
                    var_id += 1
                    continue

            raw_bytes = bytearray()
            tokens = re.findall(r'"([^"]*)"|(\d+|0x[0-9a-fA-F]+)', values_str)

            if not tokens:
                raise AssemblyCraftCompilerError(
                    f"Line {line_num}: No valid value initializers found for variable '{var_name}'."
                )

            for str_val, num_val in tokens:
                if str_val:
                    try:
                        decoded_str = str_val.encode('utf-8').decode('unicode_escape')
                        raw_bytes.extend(decoded_str.encode('utf-8'))
                    except Exception as e:
                        raise AssemblyCraftCompilerError(
                            f"Line {line_num}: Invalid escape sequence in string for '{var_name}': {e}"
                        ) from e
                elif num_val:
                    val = int(num_val, 0)
                    if size_type == 'db':
                        if not (0 <= val <= 255):
                            raise AssemblyCraftCompilerError(
                                f"Line {line_num}: Byte literal {val} out of range (0-255) in '{var_name}'."
                            )
                        raw_bytes.append(val)
                    elif size_type == 'ds':
                        raw_bytes.extend(struct.pack("<H", val & 0xFFFF))
                    elif size_type == 'dm':
                        raw_bytes.extend(struct.pack("<I", val & 0xFFFFFFFF))

            min_alloc = self.ALLOC_SIZES[size_type]
            alloc_len = max(len(raw_bytes), min_alloc)
            padded_data = bytes(raw_bytes).ljust(alloc_len, b'\x00')

            self.variables[var_name] = {
                'id': var_id,
                'size_type': size_type,
                'alloc_len': alloc_len,
                'data': padded_data
            }
            var_id += 1

    def _parse_text_section(self, lines: list):
        bytecode_offset = 0
        cleaned_instructions = []

        for line_num, line in lines:
            if line.endswith(':'):
                label_name = line[:-1].strip()
                if not label_name or not re.match(r'^[a-zA-Z_]\w*$', label_name):
                    raise AssemblyCraftCompilerError(
                        f"Line {line_num}: Invalid label identifier '{label_name}'."
                    )
                if label_name in self.labels:
                    raise AssemblyCraftCompilerError(
                        f"Line {line_num}: Duplicate label definition '{label_name}'."
                    )
                self.labels[label_name] = bytecode_offset
            else:
                cleaned_instructions.append((line_num, line))
                parts = line.split(maxsplit=1)
                args_str = parts[1] if len(parts) > 1 else ""
                num_args = len([a.strip() for a in args_str.split(',') if a.strip()]) if args_str else 0
                bytecode_offset += 1 + (num_args * 5)

        for line_num, line in cleaned_instructions:
            parts = line.split(maxsplit=1)
            mnemonic = parts[0].lower()
            args_str = parts[1] if len(parts) > 1 else ""

            if mnemonic not in self.OPCODES:
                raise AssemblyCraftCompilerError(
                    f"Line {line_num}: Unknown instruction mnemonic '{mnemonic}'."
                )

            self.bytecode.append(self.OPCODES[mnemonic])

            if args_str:
                args = [a.strip() for a in args_str.split(',') if a.strip()]
                for arg in args:
                    arg_type, arg_val = self._resolve_operand(arg, line_num)
                    self.bytecode.append(arg_type)
                    try:
                        self.bytecode += struct.pack("<i", arg_val)
                    except struct.error:
                        raise AssemblyCraftCompilerError(
                            f"Line {line_num}: Operand value {arg_val} exceeds 32-bit signed integer limits."
                        )

    def _resolve_operand(self, token: str, line_num: int = None):
        prefix = f"Line {line_num}: " if line_num else ""

        if token in self.REGISTERS:
            return self.ARG_TYPE_REG, self.REGISTERS[token]
        if token in self.variables:
            return self.ARG_TYPE_VAR, self.variables[token]['id']
        if token in self.labels:
            return self.ARG_TYPE_IMM, self.labels[token]
        try:
            return self.ARG_TYPE_IMM, int(token, 0)
        except ValueError:
            raise AssemblyCraftCompilerError(
                f"{prefix}Unresolved operand or label token '{token}'."
            )

    def _generate_binary(self) -> bytearray:
        key_table = bytearray()
        data_payload = bytearray()

        base_offset = 10 + (len(self.variables) * 25)
        current_data_offset = base_offset

        for var_name, info in self.variables.items():
            encoded_name = var_name.encode('utf-8')[:16].ljust(16, b'\x00')
            key_table += struct.pack("<B16sIH", info['id'], encoded_name, current_data_offset, info['alloc_len'])
            data_payload += info['data']
            current_data_offset += info['alloc_len']

        text_offset = current_data_offset
        header = bytearray(self.MAGIC_HEADER) + struct.pack("<HI", len(self.variables), text_offset)

        return header + key_table + data_payload + self.bytecode