import matplotlib.pyplot as plt
import numpy as np
with open("interarrival_time_vs_size.txt") as f:
    data = f.read()

data = data.split('\n')

num_lines = len(data)

print("num lines is " + str(num_lines))
i = 1

packet_sizes = []
inter_arrival_times = []

for row in data:
	print("working on %d of %d " % (i, num_lines))
	i = i + 1
	if i > 1000:
		break
	split_row = row.split(' ')
	if (len(split_row) == 2) and split_row[1] != '0': 
		inter_arrival_times.append(int(split_row[0].replace("00:00:00.", ""))) 
		packet_sizes.append(int(split_row[1]))


# now plot cdf of x
# and cdf of y in new graph
num_bins = 10
fig, ax = plt.subplots(1, 2)
n, bins, patches = ax[0].hist(packet_sizes, num_bins, density=1)
# add a 'best fit' line

mu = np.mean(packet_sizes)  # mean of distribution
sigma = np.std(packet_sizes)  # standard deviation of distribution

y = ((1 / (np.sqrt(2 * np.pi) * sigma)) *
     np.exp(-0.5 * (1 / sigma * (bins - mu))**2))
ax[0].plot(bins, y, '--')
ax[0].set_xlabel('packet size (B)')
ax[0].set_ylabel('Probability density')
ax[0].set_title(r'Histogram of packet size')

num_bins = 50
n, bins, patches = ax[1].hist(inter_arrival_times, num_bins, density=1)
# add a 'best fit' line

mu = np.mean(inter_arrival_times)  # mean of distribution
sigma = np.std(inter_arrival_times)  # standard deviation of distribution

y = ((1 / (np.sqrt(2 * np.pi) * sigma)) *
     np.exp(-0.5 * (1 / sigma * (bins - mu))**2))
ax[1].plot(bins, y, '--')
ax[1].set_xlabel('interarrival time (ms)')
ax[1].set_ylabel('Probability density')
ax[1].set_title(r'Histogram of inter arrival time')


# Tweak spacing to prevent clipping of ylabel
fig.tight_layout()
plt.show()