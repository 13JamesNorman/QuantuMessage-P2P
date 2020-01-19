"""#########################################################################
Title: QuantuMessage Encryption Algorithms          Version: 1.0

Author: James Norman                                Development Stage: 1

Start Date: 02/03/2019                              Language: Python v3.6.4

Description: Encryption and security algorithms for
             QuantuMessage messaging system

Modules: secrets, hashlib, heapq, logging, numpy, sys

Disclaimer:
Any form of encryption used within this software is experimental and has
NO PROOF OF SECURITY WHATSOEVER. Therefore it is highly recommended that
NO ONE USE THE ENCRYPTION WITHIN THIS CODE UNDER ANY CIRCUMSTANCES.

Anyone using this encryption system does so at their own risk.
The developer accepts NO RESPONSIBILITY for any loss or theft of
data as a result of using the encryption algorithms in this software.

Copyright (C) 2019 James Norman

License:
This file is part of QuantuMessage.

QuantuMessage is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

QuantuMessage is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QuantuMessage.  If not, see <https://www.gnu.org/licenses/>.
#########################################################################"""


import hashlib
import heapq as hp
import logging
import secrets
import sys

# Logger/logfile setup
formatter = logging.Formatter(fmt="%(asctime)s %(levelname)-8s %(message)s", datefmt="%d/%m/%Y %H:%M:%S")
fileWriter = logging.FileHandler("./Log/Encryption.log", mode="w")
fileWriter.setFormatter(formatter)
screenWriter = logging.StreamHandler(stream=sys.stdout)
screenWriter.setFormatter(formatter)
logger = logging.getLogger("Main")
logger.setLevel(logging.DEBUG)
logger.addHandler(fileWriter)
logger.addHandler(screenWriter)


class Dijkstra(object):
    """Class to implement Dijkstra's algorithm"""
    graph = []

    def __init__(self, graph):
        self.setGraph(graph)

    def setGraph(self, newGraph):
        """Stores the specified graph to be used when running the algorithm.
            Graphs are in the form of an adjacency matrix
            """
        if len(newGraph) == len(newGraph[0]) == len(newGraph[-1]):
            self.graph = newGraph
        
    def getGraph(self):
        """Returns the graph stored in the object"""
        return self.graph
    
    def checkList(self, current_tuple, tuple_list):
        """Checks the list of visited nodes to ensure
        that the node to be expanded isn't there, or
        that the node does not have a lower cost.
        "tuple_list" is a list of tuples with 3 parts per tuple.
        "current_tuple" is a single tuple.
        """
        pointer = 0
        while pointer < len(tuple_list):
            if tuple_list[pointer][1] == current_tuple[1]:
                if tuple_list[pointer][0] > current_tuple[0]:
                    tuple_list[pointer] = current_tuple
                return True
            else:
                pointer += 1
        return False

    def expandNode(self, node, queue):
        """Expands all nodes on the graph and
        adds costs to the priority queue"""
        for node_cost in self.graph[node[1]]:
            if node_cost < 0:
                continue
            else:
                hp.heappush(queue, (node[0] + node_cost, self.graph[node[1]].index(node_cost), node[1]))
        
    def tracePath(self, start_node, end_node, visited):
        """Retraces and returns the path
        from the end node to the start"""
        path = [end_node[1], end_node[2]]  # Last two nodes in the path.
        visited.reverse()
        
        pointer = 0
        while path[-1] != start_node:
            if visited[pointer][1] == path[-1]:
                if visited[pointer][2] in path:
                    del visited[pointer]
                    continue
                else:
                    path.append(visited[pointer][2])
                    del visited[pointer]
                    pointer = 0
            else:
                pointer += 1

        path.reverse()
        return path

    def searchGraph(self, start, end):
        """Performs Dijkstra's shortest path algorithm on the graph
        with the provided start and end positions.

        Node format: (cost, node_id, previous_node)
        """
        if start < 0 or end < 0:
            raise Exception()
        elif end > len(self.graph) - 1 or start > len(self.graph) - 1:
            raise Exception()
        else:
            visited = [] # Visited nodes placed in here to avoid repeats
            queue = [] # Priority queue
            hp.heapify(queue) 
            hp.heappush(queue, (0, start, None))
            finished = False
            while not finished:
                top_node = hp.heappop(queue)
                if top_node[1] == end:
                    finished = True
                elif self.checkList(top_node, visited) == True and len(queue) > 0:
                    continue           
                else:
                    self.expandNode(top_node, queue)
                    visited.append(top_node)

            return self.tracePath(start, top_node, visited)


class SymmetricKeyAlgorithm(object):
    """Class for symmetric-key encryption algorithm
    Encrypts strings using a provided graph with
    start and end values"""
    
    graph = []
    keys = []

    def __init__(self, graph, keys):
        """Constructs the graph and initialises the Dijkstra class to search it."""
        self.graph = graph
        self.keys = keys
        self.dijkstra = Dijkstra(self.graph)

    def toBinary(self, num):
        """Converts input integer to binary."""
        return bin(num)[2:]

    def fromBinary(self, num):
        """Converts binary input value to a base-10 integer."""
        return int(num, 2)

    def encryptMessage(self, message, start, end):
        """Encrypts messages using the graph with the provided start and end values."""
        if len(message) < 1:
            raise Exception
        else:
            path = self.dijkstra.searchGraph(start, end)
            key = self.generateKeys(path)
            return self.XOR(message, key)

    def generateKeys(self, path):
        """Generates a key based on the key list and the provided path"""
        key = ""
        for node in path:
            key = key + str(self.keys[node])
        return key


    def XOR(self, message, key):
        """Performs bitwise XOR on the message with the key provided and returns the result"""

        # A method using matrices was attempted but involved variable
        # length input and non-invertible binary matrices. This method
        # was abandoned.
        encrypted = ""
        pointer = 0
        for char in message:
            encrypted = encrypted + chr(ord(char) ^ int(str(key)[pointer]))  # XORs the message and the key.
            pointer += 1
            pointer = pointer % len(key)
        logger.info("Message encrypted")
        return encrypted

    def decryptMessage(self, message, start, end):
        """Decrypts messages using the graph with the provided start and end values."""
        return self.encryptMessage(message, start, end)  # Encryption and decryption algorithms are identical

    def setGraph(self, newGraph):
        """Stores the graph in the object along with the Dijkstra object to be used when encrypting messages."""
        if len(newGraph) == len(newGraph[0]):
            self.graph = newGraph
            self.dijkstra.setGraph(newGraph)
        else:
            raise Exception

    def getGraph(self):
        """Returns graph stored in the object"""
        return self.graph

    def setKeys(self, newkeys):
        """Stores the specified keys in the keys attribute"""
        self.keys = newkeys

    def getKeys(self):
        """Returns the contents of the keys attribute"""
        return self.keys


class SignatureAlgorithm(object):
    """Generates and verifies one-time Lamport signatures"""
    number_of_bits = 256
    
    secureNumbers = []
    secureHashes = []
    
    def __init__(self):
        self.generateSecureNumbers()

    def generateSecureNumbers(self):
        """Generates 256 pairs of numbers and a corresponding set of 256 hash pairs"""
        numbers = []
        for i in range(self.number_of_bits):  # Loop generates 256 pairs of random numbers
            pair = (secrets.randbits(256), secrets.randbits(256))
            numbers.append(pair)
        hashes = []
        for pair in numbers:
            part1 = self.hashValue(str(pair[0]))
            part2 = self.hashValue(str(pair[1]))
            hashes.append((part1, part2))

        self.secureNumbers = numbers
        self.secureHashes = hashes

    def toBinary(self, num):
        """Converts input integer to binary"""
        return bin(num)[2:]

    def fromBinary(self, num):
        """Converts binary input value to a base-10 integer"""
        return int(num, 2)
    
    def hashValue(self, value):
        """Hashes the value to a 512-bit sum using sha3 then returns a base-10 form"""
        return int(str(hashlib.sha3_256(value.encode()).hexdigest()), 16)         

    def signMessage(self, message):
        """Generates a one-time Lamport signature for the provided message"""
        if len(message) < 1:
            raise Exception
        else:
            hashed_message = self.toBinary(self.hashValue(str(message)))
            hashes = self.secureHashes
            numbers = []
            for pair in self.secureNumbers:  # Follows the standard algorithm for
                for char in str(hashed_message):  # generating a Lamport signature
                    numbers.append(pair[int(char)])
            self.generateSecureNumbers()
            return numbers, hashes

    def checkSignature(self, message, numbers, hashes):
        """Verifies the one-time Lamport signature provided with the message."""
        isValid = False
        hashed_message = self.toBinary(self.hashValue(str(message)))
        selected_hashes = []
        hashed_numbers = []
        for pair in hashes:
            for char in str(hashed_message):
                selected_hashes.append(pair[int(char)])
        for number in numbers:
            hashedNumber = self.hashValue(str(number))
            hashed_numbers.append(hashedNumber)
        if selected_hashes == hashed_numbers:
            isValid = True
        return isValid

    def getSecureNumbers(self):
        """Returns the 512 numbers used when signing a message"""
        return self.secureNumbers
