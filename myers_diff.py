from collections import deque

ansi_green_bg = "\x1b[42m"
ansi_red_bg = "\x1b[41m"
ansi_reset = "\x1b[0m"

uno = "In 1986, Eugene Myers published An O(ND) Difference Algoritm and Its Variations"
due = "In 1987 Eugne Myers published And Osdf(ND) Difdfsfsfence Algorithm Its variations"

with open("index.md") as f:
    uno = f.read()

with open("README.md") as f:
    due = f.read()

due = [x+'\n' for x in due.splitlines()]
uno = [x+'\n' for x in uno.splitlines()]

grid = [[1 if d==u else 0 for d in due]+[0] for u in uno]+ [[0 for _ in range(len(due)+1)]]

bfs = deque()

bfs.append((0, 0, ""))

def set_visited(i, j):
    grid[i][j] = -2 if grid[i][j] == 1 else -1

# myers diff
while bfs:
    i, j, path = bfs.popleft()
    if i == len(uno) and j == len(due):
        print(path)
        break

    if grid[i][j] in (-2, 1) and grid[i+1][j+1] >= 0:
        bfs.append((i + 1, j + 1, path + uno[i]))
        set_visited(i+1, j+1)

    else:
        if i < len(uno) and grid[i+1][j] >= 0:
            bfs.append((i + 1, j, path + ansi_red_bg + uno[i] + ansi_reset))
            set_visited(i+1, j)
            
        if j < len(due) and grid[i][j+1] >= 0:
            bfs.append((i, j + 1, path + ansi_green_bg + due[j] + ansi_reset))
            set_visited(i, j+1)

