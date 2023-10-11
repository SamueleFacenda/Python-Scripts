// iterate over all the unicode characters and print out all of them

for (var i = 0; i < 0xfffff; i++) {
    var c = String.fromCharCode(i);
    if (c.normalize() == '\'') {
        console.log("Found it! " + i);
        console.log(c);
    }
}
