# gnuplot --persist plot.gnu

set datafile separator ','
set xdata time
set output "plot.png"
set timefmt "%Y-%m-%dT%H:%M:%S"
set key autotitle columnhead
set ylabel "First Y Units"
set xlabel 'Time'
set y2tics
set ytics nomirror
set y2label "Second Y Axis Value"
set style line 100 lt 1 lc rgb "grey" lw 0.5
set grid ls 100
set ytics 0.5
set xtics 1
set style line 101 lw 3 lt rgb "#f62aa0"
set style line 102 lw 3 lt rgb "#26dfd0"
set style line 103 lw 4 lt rgb "#b8ee30"

set xtics rotate # rotate labels on the x axis
set key right center # legend placement

plot "data.csv" using 1:2 with lines ls 101, '' using 1:3 with lines ls 102, '' using 1:4 with lines axis x1y2 ls 103