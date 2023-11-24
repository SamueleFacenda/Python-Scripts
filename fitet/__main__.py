from . import FitetParser, Player
from argparse import ArgumentParser
import sys

def main():
    parser = ArgumentParser()
    parser.add_argument('--dump-path', '-d',type=str, default="db.sqlite3", dest="dump_path", help="Path to the sqlite3 dump")
    parser.add_argument('--region', '-r', action='append', dest="regions", help="Regions to search for", default=["Trentino"])
    parser.add_argument('--update', '-u', action='store_true', dest="update", help="Update the database")
    parser.add_argument('players', type=str, nargs='*', help="Players to search for")

    args = parser.parse_args()
        
    parser = FitetParser(args.dump_path)
    if args.update:
        parser.update(args.regions)
    print(len(parser.matches))
    
    for player in args.players:
        player = Player.get(parser.persistency, player)
        print(player.pretty_str())
        
        
        
if __name__ == "__main__":
    main()
