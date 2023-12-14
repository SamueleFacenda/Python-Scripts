#include <iostream>
#include <cstdlib>

using namespace std;

void StampaFrazioneEgizia(const int, const int);

int main(int argc, char ** argv) {
  if (argc != 3) {
    std::cout << "Usage: " << argv[0] << " <numerator_positivenum> <denominator_positivenum>" << std::endl;
    exit(1);
  }
  int num = atoi(argv[1]);
  int den = atoi(argv[2]);


  cout << "Frazione iniziale:"
       << num << "/" << den << " is" << endl;
  cout << "Frazione egizia: ";
  StampaFrazioneEgizia(num, den);
}

void StampaFrazioneEgizia(const int num, const int den) {
    if (!num || !den) {
        cout << endl;
        return;
    }

    if (num % den == 0) {
        cout << num / den << endl;
        return;
    }

    if (den % num == 0) {
        cout << "1/" << den / num << endl;
        return;
    }

    if (num > den) {
        cout <<num / den << " ";
        StampaFrazioneEgizia(num%den, den);
    } else {
        int x = den / num + 1;
        cout << "1/" << x << " ";
        StampaFrazioneEgizia(num*x-den, den*x);
    }
}