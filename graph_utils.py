import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
import sys
import matplotlib
import numpy as np
from math import sqrt
SPINE_COLOR = 'gray'


def no_zeroes(data):
    non_zero = 0
    for element in data:
        if element > 0:
            non_zero += 1

    new_data = [0] * (non_zero)
    insert_index = 0
    for element in data:
        if element > 0:
            new_data[insert_index] = element
            insert_index += 1

    print "Removed ", len(data) - non_zero, "entries that were all zero"
    print "Before this, there were ", len(data), "entries"
    return new_data


def get_logspace(min_lim, max_lim):
    assert min_lim != 0 # We can't handle zeroes...
    small_diff_upper = max_lim / 10000.0
    small_diff_lower = - (min_lim / 10000.0)

    logspace_bins = np.append(np.logspace(np.log10(min_lim + small_diff_lower), np.log10(max_lim + small_diff_upper), 1000), np.inf)

    return logspace_bins


def get_linspace(min_lim, max_lim):
    small_diff_lower = - (abs(min_lim) / 10000.0)
    small_diff_upper = max_lim / 10000.0

    linspace_bins = \
        np.append(np.linspace((min_lim + small_diff_lower),
                  (max_lim + small_diff_upper), 1000), np.inf)

    return linspace_bins


def set_integer_ticks():
    ax = plt.gca()
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))


def set_log_x():
    ax = plt.gca()
    ax.set_xscale('log')


def set_log_y():
    ax = plt.gca()
    ax.set_yscale('log')


def set_legend_below(extra=0.0, ncol=2):
    ax = plt.gca()
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.20 - extra),
              fancybox=True, shadow=True, ncol=ncol)


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


def latexify(fig_width=None, fig_height=None, columns=2, space_below_graph=0.0, bottom_label_rows=0):
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

    # Add some height for the labels.
    fig_height += space_below_graph
    # Make the graph taller to account for the labels at the
    # bottom of the graph.
    fig_height += bottom_label_rows * 0.33
    if bottom_label_rows > 0:
        # And a bit to make up for the padding at the beginning
        # and end of such a label box
        fig_height += 0.2

    MAX_HEIGHT_INCHES = 8.0
    if fig_height > MAX_HEIGHT_INCHES:
        print("WARNING: fig_height too large:" + fig_height + 
              "so will reduce to" + MAX_HEIGHT_INCHES + "inches.")
        fig_height = MAX_HEIGHT_INCHES

    params = {# 'backend': 'ps',
              'text.latex.preamble': ['\\usepackage{gensymb}'],
              'axes.labelsize': 12, # fontsize for x and y labels (was 10)
              'axes.titlesize': 12,
              # 'text.fontsize': 8, # was 10
              'legend.fontsize': 12, # was 10
              'xtick.labelsize': 12,
              'ytick.labelsize': 12,
              # 'text.usetex': True,
              'figure.figsize': [fig_width,fig_height],
              'font.family': 'serif',
              'figure.autolayout': True,
              'patch.linewidth': 1.3
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
