from . import FitetParser, Player
import sys

def main():
    dump_path = None # Default dump path
    if len(sys.argv) > 1:
        dump_path = sys.argv[1]
    else:
        dump_path = "fitet/matches.json"
        
    parser = FitetParser(dump_path)
    parser.update(["Trentino"])
    print(len(parser.matches))
    for match in Player.get("Facenda Samuele").matches: print(match)

if __name__ == "__main__":
    main()
