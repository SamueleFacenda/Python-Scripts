from . import FitetParser, Player
from argparse import ArgumentParser

def main():
    parser = ArgumentParser()
    parser.add_argument('--dump-path', '-d',type=str, default=None, dest="dump_path", help="Path to the sqlite3 dump")
    parser.add_argument('--region', '-r', action='append', dest="regions", help="Regions to search for", default=["Trentino"])
    parser.add_argument('--update', '-u', action='store_true', dest="update", help="Update the database")
    parser.add_argument('--query', '-q', action='append', dest="queries", default=[], help="Players to search for")
    parser.add_argument('--verbose', '-v', action='store_true', dest="verbose", help="Verbose")
    parser.add_argument('players', type=str, nargs='*', help="Players to search for")

    args = parser.parse_args()
        
    parser = FitetParser(args.dump_path, verbose=args.verbose)
    if args.update:
        parser.update(args.regions)

    print(len(parser.matches))# can do a select count
    
    for player in args.players + args.queries:
        player = Player.get(parser.persistency, player)
        print(player.pretty_str())
        
        
        
if __name__ == "__main__":
    main()
83