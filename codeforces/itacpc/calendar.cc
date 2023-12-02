#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

using namespace std;

struct meeting {
    int start;
    int end;
    int overlaps;
    bool is_open = true;
};

int main() {
    vector<meeting> open_meetings = {};
    vector<meeting> meetings = {};

    int N, meetings_to_eliminate;

    cin >> N >> meetings_to_eliminate;

    for (int i = 0; i < N; i++) {
        int start, end;
        cin >> start >> end;
        meetings.push_back({start, end});
    }

    // we need to sort the meetings by start time
    sort(meetings.begin(), meetings.end(), [](meeting a, meeting b) {
        return a.start < b.start;
    });

    // we loop through the meetings and add them to the open meetings vector
    // if the open meetings vector is empty we add the current meeting to it
    // if the open meetings vector is not empty we check if the current meeting
    // overlaps with the series of last meetings in the open meetings vector
    // we increment the overlaps counter for the current meeting if it overlaps and for the open range meeting

    for (auto & meeting : meetings) {
        if (open_meetings.empty()) {
            open_meetings.push_back(meeting);
        } else {
            for (auto & open_meeting : open_meetings) {
                if (open_meeting.is_open) {
                    if (meeting.start <= open_meeting.end) {
                        meeting.overlaps++;
                        open_meeting.overlaps++;
                    }

                    if (meeting.start >= open_meeting.end) {
                        //closed_meetings.push_back(open_meeting);
                        //open_meetings.erase(open_meetings.begin());
                        open_meeting.is_open = false;
                    }
                }
            }
            open_meetings.push_back(meeting);
        }
    }

    // we add the remaining open meetings to the closed meetings vector
//    for (auto & open_meeting : open_meetings) {
//        closed_meetings.push_back(open_meeting);
//    }

    // we sort the meetings by the number of overlaps
    sort(open_meetings.begin(), open_meetings.end(), [](meeting a, meeting b) {
        return a.overlaps > b.overlaps;
    });

    // we print the meetings with the most overlaps: start, end, # overlaps
    for (auto & meeting : open_meetings) {
        cout << meeting.start << " " << meeting.end << " " << meeting.overlaps << endl;
    }

    cout << open_meetings.at(meetings_to_eliminate).overlaps - meetings_to_eliminate + 1 << endl;

    return 0;
}

/*
 * 5 2
0 6
3 7
6 7
0 8
3 6
 */