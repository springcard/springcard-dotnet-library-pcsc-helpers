import re
import sys
import os
import shutil

def convert_doxygen_slash_to_at(text):
    # Remplacement des balises Doxygen \xxx par @xxx
    text = re.sub(r'\\defgroup', '@addtogroup', text)
    text = re.sub(r'\\brief', '@brief', text)
    text = re.sub(r'\\author', '@author', text)
    text = re.sub(r'\\copyright', '@copyright', text)
    text = re.sub(r'\\param', '@param', text)
    text = re.sub(r'\\return', '@return', text)
    text = re.sub(r'\\note', '@note', text)
    text = re.sub(r'\\see', '@see', text)
    text = re.sub(r'\\ingroup', '@ingroup', text)
    text = re.sub(r'\\fn', '@fn', text)
    text = re.sub(r'\\file', '@file', text)
    text = re.sub(r'\\class', '@class', text)
    text = re.sub(r'\\struct', '@struct', text)
    text = re.sub(r'\\var', '@var', text)
    text = re.sub(r'\\code', '@code', text)
    text = re.sub(r'\\endcode', '@endcode', text)
    return text

def convert_robodoc_to_doxygen(text):
    # Conversion Robodoc → Doxygen (voir script précédent)
    text = re.sub(r"/\*\*h\*.*?\*/", lambda m: convert_header(m.group()), text, flags=re.DOTALL)
    text = re.sub(r"/\*\*c\*.*?\*/", lambda m: convert_class(m.group()), text, flags=re.DOTALL)
    text = re.sub(r"/\*\*f\*.*?\*/", lambda m: convert_function(m.group()), text, flags=re.DOTALL)
    text = re.sub(r"/\*\*m\*.*?\*/", lambda m: convert_function(m.group()), text, flags=re.DOTALL)
    text = re.sub(r"/\*\*v\*.*?\*/", lambda m: convert_variable(m.group()), text, flags=re.DOTALL)
    text = re.sub(r"/\*\*t\*.*?\*/", lambda m: convert_struct(m.group()), text, flags=re.DOTALL)
    return text

def extract_field(block, field):
    m = re.search(r"^\s*\*\s*%s\s*(.*?)$" % field, block, re.MULTILINE)
    return m.group(1).strip() if m else ""

def convert_header(block):
    name = extract_field(block, "NAME")
    copyright = extract_field(block, "COPYRIGHT")
    description = extract_field(block, "DESCRIPTION")
    return f"""/**\n * @file\n * @brief {name}\n * @details {description}\n * @copyright {copyright}\n */"""

def convert_class(block):
    name = extract_field(block, "NAME")
    description = extract_field(block, "DESCRIPTION")
    return f"""/**\n * @class {name}\n * @brief {description}\n */"""

def convert_function(block):
    name = extract_field(block, "NAME")
    description = extract_field(block, "DESCRIPTION")
    synopsis = extract_field(block, "SYNOPSIS")
    returns = extract_field(block, "RETURNS")
    notes = extract_field(block, "NOTES")
    doc = "/**\n"
    if name:
        doc += f" * @fn {name}\n"
    if description:
        doc += f" * @brief {description}\n"
    if synopsis:
        doc += f" * @details\n * {synopsis}\n"
    if returns:
        doc += f" * @return {returns}\n"
    if notes:
        doc += f" * @note {notes}\n"
    doc += " */"
    return doc

def convert_variable(block):
    name = extract_field(block, "NAME")
    description = extract_field(block, "DESCRIPTION")
    return f"""/**\n * @var {name}\n * @brief {description}\n */"""

def convert_struct(block):
    name = extract_field(block, "NAME")
    description = extract_field(block, "DESCRIPTION")
    return f"""/**\n * @struct {name}\n * @brief {description}\n */"""

def process_file(filename):
    with open(filename, "r", encoding="utf-8") as f:
        content = f.read()
    # Conversion Robodoc → Doxygen
    new_content = convert_robodoc_to_doxygen(content)
    # Conversion des balises \xxx → @xxx
    new_content = convert_doxygen_slash_to_at(new_content)
    # Sauvegarde du fichier original
    backup_filename = filename + ".bak"
    shutil.copy2(filename, backup_filename)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(new_content)
    print(f"Converti : {filename} (backup : {backup_filename})")

def process_directory(directory, extensions=(".cs", ".c", ".h")):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(extensions):
                process_file(os.path.join(root, file))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage : python robodoc2doxygen.py <répertoire> [ext1 ext2 ...]")
        sys.exit(1)
    directory = sys.argv[1]
    if len(sys.argv) > 2:
        extensions = tuple(sys.argv[2:])
    else:
        extensions = (".cs", ".c", ".h")
    process_directory(directory, extensions)
