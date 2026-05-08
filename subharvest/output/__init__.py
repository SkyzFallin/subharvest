from subharvest.output.json_writer import write_json
from subharvest.output.txt_writer import write_txt
from subharvest.output.csv_writer import write_csv
from subharvest.output.markdown_writer import write_markdown

WRITERS = {
    "json": write_json,
    "txt": write_txt,
    "csv": write_csv,
    "md": write_markdown,
}

__all__ = ["WRITERS", "write_json", "write_txt", "write_csv", "write_markdown"]
