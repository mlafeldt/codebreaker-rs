# v10 model selection for the shared firmware/crate comparison driver.
# usage: python3 -I emudiff10.py <CBv10.unpacked.bin> <emu.out> <crate.out> [plain.txt]
# Exit 0: agreement / exact --expected baseline; 1: differences; 2: bad input.
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from emudiff import main
from fwmodel10 import Fw10, Image10, Tables10


if __name__ == '__main__':
    sys.exit(main(fw_class=Fw10, image_class=Image10, table_class=Tables10))
