#include <vector>

class Flag {
    std::vector<char> *flag;
public:
    Flag() {
        flag = new std::vector<char>({102,108,97,103,123,81,85,69,83,84,65,95,70,76,65,71,95,69,39,95,83,73,67,85,82,65,77,69,78,84,69,95,85,78,65,95,70,76,65,71,95,86,69,82,65,125});
    }
};

// Il tuo codice va qua
int main(){
    Flag flag = Flag();
    
    

}