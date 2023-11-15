from . import FitetParser, Player
import sys

def main():
    dump_path = "fitet/matches.json"
        
    search_players = [x for x in sys.argv[1:] if '--dump-path=' not in x]
    dump_list = [x for x in sys.argv[1:] if '--dump-path=' in x]
    if dump_list:
        dump_path = dump_list[0].split('=')[1]
    
        
    parser = FitetParser(dump_path)
    parser.update(["Trentino"])
    print(len(parser.matches))
    
    for player in search_players:
        matches = Player.get(player).matches
        print()
        print('#'*(len(player)+6))
        print('##' ,player, '##')
        print('#'*(len(player)+6))
        print('\n'.join([str(x) for x in matches]))
        
        
        
if __name__ == "__main__":
    main()
