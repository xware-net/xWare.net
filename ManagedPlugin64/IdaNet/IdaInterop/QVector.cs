using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    public class QVector<T> : IEnumerable<T> where T: class, IMarshalable
    {
        private T[] array;
        private int size;
 
        public IntPtr UnmanagedPtr { get; set; }

        // Constructor
        public QVector()
        {
            array = new T[4]; // Start with a small capacity
            size = 0;
        }

        public QVector(IntPtr ptr)
        {
            UnmanagedPtr = ptr;
            
            // must populate the array and size
        }

        // Copy constructor
        public QVector(QVector<T> other)
        {
            size = other.size;
            array = new T[other.size];
            Array.Copy(other.array, array, other.size);
        }

        // Move constructor equivalent not needed in C# due to garbage collection

        // Destructor (not needed in C# due to garbage collection)

        // Add a new element to the end
        public void PushBack(T item)
        {
            EnsureCapacity(size + 1);
            array[size++] = item;
        }

        // Remove the last element
        public void PopBack()
        {
            if (size > 0)
            {
                array[--size] = default(T); // Remove reference for GC
            }
        }

        // Resize the vector
        public void Resize(int newSize, T defaultValue = default(T))
        {
            if (newSize < size)
            {
                // Shrink: Reset elements beyond newSize
                for (int i = newSize; i < size; i++)
                {
                    array[i] = default(T); // Clear for GC
                }
            }
            else if (newSize > size)
            {
                // Grow: Initialize new elements
                EnsureCapacity(newSize);
                for (int i = size; i < newSize; i++)
                {
                    array[i] = defaultValue;
                }
            }
            size = newSize;
        }

        // Get number of elements
        public int Size => size;

        // Get the capacity
        public int Capacity => array.Length;

        // Check if the vector is empty
        public bool IsEmpty => size == 0;

        // Indexer for element access
        public T this[int index]
        {
            get
            {
                if (index < 0 || index >= size)
                    throw new ArgumentOutOfRangeException(nameof(index));
                return array[index];
            }
            set
            {
                if (index < 0 || index >= size)
                    throw new ArgumentOutOfRangeException(nameof(index));
                array[index] = value;
            }
        }

        // Front element
        public T Front()
        {
            if (size == 0) 
                throw new InvalidOperationException("Vector is empty.");
            return array[0];
        }

        // Back element
        public T Back()
        {
            if (size == 0) 
                throw new InvalidOperationException("Vector is empty.");
            return array[size - 1];
        }

        // Clear the vector
        public void Clear()
        {
            for (int i = 0; i < size; i++)
            {
                array[i] = default(T); // Clear for GC
            }
            size = 0;
        }

        // Insert element at specified position
        public void Insert(int index, T item)
        {
            if (index < 0 || index > size)
                throw new ArgumentOutOfRangeException(nameof(index));

            EnsureCapacity(size + 1);
            Array.Copy(array, index, array, index + 1, size - index);
            array[index] = item;
            size++;
        }

        // Remove element at specified position
        public void Erase(int index)
        {
            if (index < 0 || index >= size)
                throw new ArgumentOutOfRangeException(nameof(index));

            Array.Copy(array, index + 1, array, index, size - index - 1);
            array[--size] = default(T); // Clear for GC
        }

        // Find the index of an element
        public int IndexOf(T item)
        {
            for (int i = 0; i < size; i++)
            {
                if (EqualityComparer<T>.Default.Equals(array[i], item))
                    return i;
            }
            return -1;
        }

        // Check if the vector contains an element
        public bool Contains(T item)
        {
            return IndexOf(item) != -1;
        }

        // Ensure the internal array has enough capacity
        private void EnsureCapacity(int minCapacity)
        {
            if (minCapacity > array.Length)
            {
                int newCapacity = array.Length * 2;
                if (newCapacity < minCapacity)
                    newCapacity = minCapacity;
                Array.Resize(ref array, newCapacity);
            }
        }

        // Enumerator to allow foreach iteration
        public IEnumerator<T> GetEnumerator()
        {
            for (int i = 0; i < size; i++)
            {
                yield return array[i];
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }

    internal class Marshaler : ICustomMarshaler
    {
        private Marshaler()
        {
        }

        public static ICustomMarshaler GetInstance(string cookie)
        {
            return _singleton;
        }

        public void CleanUpManagedData(object ManagedObj)
        {
            throw new NotImplementedException();
        }

        public void CleanUpNativeData(IntPtr pNativeData)
        {
            throw new NotImplementedException();
        }

        public int GetNativeDataSize()
        {
            throw new NotImplementedException();
        }

        public IntPtr MarshalManagedToNative(object ManagedObj)
        {
            throw new NotImplementedException();
        }

        public object MarshalNativeToManaged(IntPtr pNativeData)
        {
            throw new NotImplementedException();
        }

        private static readonly Marshaler _singleton = new Marshaler();
    }
}
