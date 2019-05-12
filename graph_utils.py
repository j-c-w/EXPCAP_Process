import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
import sys


def set_integer_ticks():
    ax = plt.figure().gca()
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))


def set_ticks():
    (xmin, xmax) = plt.xlim()
    (ymin, ymax) = plt.ylim()

    if xmin == xmax or ymin == ymax:
        print "Error, have you plotted anything yet?"
        print " You need ot have plotted data before calling add_grid()"
        sys.exit(1)

    ax = plt.gca()
    ax.set_axisbelow(True)
    plt.grid()


def set_non_negative_axes():
    (xmin, xmax) = plt.xlim()
    (ymin, ymax) = plt.ylim()

    if xmin < 0:
        plt.xlim(0, xmax)
    if ymin < 0:
        plt.ylim(0, ymax)


def set_yax_max_one():
    (ymin, ymax) = plt.ylim()
    if ymax > 1:
        plt.ylim(ymin, 1)


def legend_bottom_right():
    plt.legend(loc='lower right')


def legend_upper_left():
    plt.legend(loc='upper left')
