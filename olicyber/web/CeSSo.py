from bs4 import BeautifulSoup
from tqdm import tqdm
import pickle
import png

class coso():
    def __init__(self):
        self.color = ""
        self.animNum = -1
        self.start = (0,0)
        self.end = (0,0)
        self.position = (0,0)


def parser():
    file = open("C:\\Users\\samue\\Downloads\\css-shitty-scaling\\flag.html", "r")
    html = file.read()
    file.close()

    print("file read done")

    soup = BeautifulSoup(html, "html.parser")

    print("soup done")
    with open("media/soup.pickle", "wb") as f:
        pickle.dump(str(soup), f)

    # get all div with table-row in style
    divs = soup.find_all("div", style=lambda value: value and "table-row" in value)
    print("rows done")

    # get all css keyframes
    keyframes = soup.find_all("style")
    print("keyframes done")

    dicto = {}
    for row, div in tqdm(enumerate(divs)):
        for col, child in enumerate(div.find_all("div", style=lambda value: value and "animation" in value)):
            num = child["style"].split("slide")[1].split(" ")[0]
            num = int(num)
            color = child["style"].split("background-color:")[1].split(";")[0]
            dicto[num] = coso()
            dicto[num].color = color
            dicto[num].animNum = num
            dicto[num].position = (col, row)

    print("div scan done")


    for k in tqdm(keyframes):
        num = k.text.split("slide")[1].split("{")[0].strip()
        num = int(num)
        transorm = k.text.split("translate")[1:]
        transorm = [x.split(")")[0][1:] for x in transorm]
        transorm = [x.split(",") for x in transorm]
        fromo = tuple([int(x[:-2]) for x in transorm[0]])
        too = tuple([int(x[:-2]) for x in transorm[1]])
        dicto[num].start = fromo
        dicto[num].end = too

    print("keyframes scan done")

    for k in tqdm(dicto):
        el = dicto[k]
        el.position = (el.start[0] + el.end[0]) / 2 + el.position[0], (el.start[1] + el.end[1]) / 2 +el.position[1]
    # dump with pickle
    with open("media/flag.pickle", "wb") as f:
        pickle.dump(dicto, f)

def binfromcolor(color):
    if "00000000" in color:
        return "0"
    elif "000000ff" in color:
        return "1"
    else:
        return "?"

def analyze():
    with open("flag.pickle", "rb") as f:
        dicto = pickle.load(f)

    # group by row
    rows = {}
    for k in tqdm(dicto, desc="grouping"):
        el = dicto[k]
        if el.position[1] not in rows:
            rows[el.position[1]] = []
        rows[el.position[1]].append(el)

    # sort by column
    for k in rows:
        rows[k] = sorted(rows[k], key=lambda x: x.position[0])

    # print in file
    file = open("flag.txt", "w")
    for k in sorted(rows):
        for el in rows[k]:
            file.write(binfromcolor(el.color))
        file.write("\n")
    file.close()

# analyze()

# https://gchq.github.io/CyberChef/#recipe=Fork('%5C%5Cn','%5C%5Cn',false)Substitute('?','1',false)From_Binary('Space',8)Detect_File_Type(true,true,true,true,true,true,true)Merge(true)

# it is an image, print it in a file as an ascii art

def intfromcolor(color):
    if "00000000" in color:
        return 0
    elif "000000ff" in color:
        return 255
    else:
        return 128



def printimage():
    with open("media/flag.pickle", "rb") as f:
        dicto = pickle.load(f)

    maxX = max([int(x.position[0]) for x in dicto.values()])
    maxY = max([int(x.position[1]) for x in dicto.values()])
    minX = min([int(x.position[0]) for x in dicto.values()])
    minY = min([int(x.position[1]) for x in dicto.values()])
    print(maxX, maxY)
    print(minX, minY)

    grid = [[0 for _ in range(int(maxX-minX+2))] for __ in range(int(maxY-minY+2))]

    for k in tqdm(dicto):
        el = dicto[k]
        grid[int(el.position[1]-minY)][int(el.position[0]-minX)] = intfromcolor(el.color)

    f = open('media/ramp.png', 'wb')
    w = png.Writer(len(grid[0]),len(grid), greyscale=True)
    w.write(f, grid)
    f.close()

parser()
printimage()
