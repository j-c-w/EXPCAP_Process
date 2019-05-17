import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
import sys
import matplotlib
from math import sqrt
SPINE_COLOR = 'gray'


def set_integer_ticks():
    ax = plt.gca()
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


# This saves the multiple ways in which we might want to view
# a CDF.
def save_cdf(filename, use_xlims=None):
    plt.savefig(filename + '.eps')


def legend_bottom_right():
    plt.legend(loc='lower right')


def legend_upper_left():
    plt.legend(loc='upper left')


def latexify(fig_width=None, fig_height=None, columns=2):
    """Set up matplotlib's RC params for LaTeX plotting.
    Call this before plotting a figure.

    Parameters
    ----------
    fig_width : float, optional, inches
    fig_height : float,  optional, inches
    columns : {1, 2}
    """

    # code adapted from http://www.scipy.org/Cookbook/Matplotlib/LaTeX_Examples

    # Width and max height in inches for IEEE journals taken from
    # computer.org/cms/Computer.org/Journal%20templates/transactions_art_guide.pdf

    assert(columns in [1,2])

    if fig_width is None:
        fig_width = 3.39 if columns==1 else 6.9 # width in inches

    if fig_height is None:
        golden_mean = (sqrt(5)-1.0)/2.0    # Aesthetic ratio
        fig_height = fig_width*golden_mean # height in inches

    MAX_HEIGHT_INCHES = 8.0
    if fig_height > MAX_HEIGHT_INCHES:
        print("WARNING: fig_height too large:" + fig_height + 
              "so will reduce to" + MAX_HEIGHT_INCHES + "inches.")
        fig_height = MAX_HEIGHT_INCHES

    params = {# 'backend': 'ps',
              'text.latex.preamble': ['\\usepackage{gensymb}'],
              'axes.labelsize': 10, # fontsize for x and y labels (was 10)
              'axes.titlesize': 10,
              # 'text.fontsize': 8, # was 10
              'legend.fontsize': 10, # was 10
              'xtick.labelsize': 10,
              'ytick.labelsize': 10,
              # 'text.usetex': True,
              'figure.figsize': [fig_width,fig_height],
              'font.family': 'serif',
              'figure.autolayout': True
    }

    matplotlib.rcParams.update(params)


def format_axes(ax):
    for spine in ['top', 'right']:
        ax.spines[spine].set_visible(False)

    for spine in ['left', 'bottom']:
        ax.spines[spine].set_color(SPINE_COLOR)
        ax.spines[spine].set_linewidth(0.5)

    ax.xaxis.set_ticks_position('bottom')
    ax.yaxis.set_ticks_position('left')

    for axis in [ax.xaxis, ax.yaxis]:
        axis.set_tick_params(direction='out', color=SPINE_COLOR)

    return ax


# Call this regardless.
print "Graph utils is overwriting the Matplotlib RC"
latexify()
