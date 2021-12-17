"""
A simple maths class that helps calculate a Rolling Average of at most n values.
"""


class RollingAverage:

    def __init__(self, max_dp=100):
        """
        max_dp: The most amount of data points that will be used for the rolling average.
        """
        if not max_dp > 0:
            raise ValueError("Cannot create a rolling average of " + str(max_dp) + " data points"
                                                                                   " (must be greater than 0).")

        self.storage = [0]*max_dp   # The storage of all the data points.
        self.next_idx = 0           # The next index in the circular storage.
        self.is_full = False        # If we have reached the maximum amount of data points for our rolling average.
        self.result = 0             # The actual rolling average.

    def add_value(self, value):
        """
        Add a data point to the rolling average, returning the new average.
        """
        if self.is_full:  # Simple moving average. Need to look at value at current index before overriding it.
            self.result += (value - self.storage[self.next_idx]) / (len(self.storage))  # Get the delta div. max_dp.
        else:             # Cumulative moving average. Our n is not yet at maximum, and no array access is necessary.
            self.result += (value - self.result) / (self.next_idx + 1)

        self.storage[self.next_idx] = value  # Store this value on the buffer.
        self.next_idx = self.__get_next_idx()                 # Calculate the index for next time.
        return self.get_avg()                   # Return the new average.

    def __get_next_idx(self):
        """
        Calculates the next index into self.storage.
        """
        nxt = (self.next_idx + 1) % len(self.storage)

        if nxt == 0:  # We looped back to the start of the circular buffer, meaning we've run out of space.
            self.is_full = True  # Is assigning a value computationally cheaper than comparing a value?

        return nxt

    def get_avg(self):
        return self.result

    def __str__(self):
        return str(self.get_avg())


if __name__ == "__main__":
    rl = RollingAverage(100)
    print(rl.add_value(50))     # 50.0
    print(rl.add_value(50))     # 50.0
    print(rl.add_value(0))      # 33.3333... (because 100 / 3)
    print(rl)                   # 33.3333... (should still be the same)
    rl.add_value(0)
    print(rl.get_avg())         # should be 25.0, but is actually 24.99999999... due to floating point error.

    one = RollingAverage(1)
    print(one.add_value(999))   # 999.0
    if not one.is_full:
        raise AttributeError("Rolling Average 'one' is meant to be marked as full but is not.")
    print(one.add_value(-2))    # -2.0 (the average of 1 data-point is just that data-point)

    try:
        RollingAverage(0)       # A rolling average of 0 data points does not make sense. Attempting to do so
    except ValueError as e:     # would create ZeroDivisionError or IndexError exceptions at some point.
        print(e)
    else:
        raise RuntimeError("TEST FAIL: Created a Rolling Average of 0 data points.")

    try:
        RollingAverage(-7)      # A rolling average of a negative amount of data points also does not make sense.
    except ValueError as e:
        print(e)
    else:
        raise RuntimeError("TEST FAIL: Created a Rolling Average of -7 data points.")
