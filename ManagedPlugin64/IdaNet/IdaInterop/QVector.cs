using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace IdaNet.IdaInterop
{
    //public class QVector<T> : IEnumerable<T> where T: class, IMarshalable
    //{
    //    private T[] array;
    //    private int size;

    //    public IntPtr UnmanagedPtr { get; set; }

    //    // Constructor
    //    public QVector()
    //    {
    //        array = new T[4]; // Start with a small capacity
    //        size = 0;
    //    }

    //    public QVector(IntPtr ptr)
    //    {
    //        UnmanagedPtr = ptr;

    //        // must populate the array and size
    //    }

    //    // Copy constructor
    //    public QVector(QVector<T> other)
    //    {
    //        size = other.size;
    //        array = new T[other.size];
    //        Array.Copy(other.array, array, other.size);
    //    }

    //    // Move constructor equivalent not needed in C# due to garbage collection

    //    // Destructor (not needed in C# due to garbage collection)

    //    // Add a new element to the end
    //    public void PushBack(T item)
    //    {
    //        EnsureCapacity(size + 1);
    //        array[size++] = item;
    //    }

    //    // Remove the last element
    //    public void PopBack()
    //    {
    //        if (size > 0)
    //        {
    //            array[--size] = default(T); // Remove reference for GC
    //        }
    //    }

    //    // Resize the vector
    //    public void Resize(int newSize, T defaultValue = default(T))
    //    {
    //        if (newSize < size)
    //        {
    //            // Shrink: Reset elements beyond newSize
    //            for (int i = newSize; i < size; i++)
    //            {
    //                array[i] = default(T); // Clear for GC
    //            }
    //        }
    //        else if (newSize > size)
    //        {
    //            // Grow: Initialize new elements
    //            EnsureCapacity(newSize);
    //            for (int i = size; i < newSize; i++)
    //            {
    //                array[i] = defaultValue;
    //            }
    //        }
    //        size = newSize;
    //    }

    //    // Get number of elements
    //    public int Size => size;

    //    // Get the capacity
    //    public int Capacity => array.Length;

    //    // Check if the vector is empty
    //    public bool IsEmpty => size == 0;

    //    // Indexer for element access
    //    public T this[int index]
    //    {
    //        get
    //        {
    //            if (index < 0 || index >= size)
    //                throw new ArgumentOutOfRangeException(nameof(index));
    //            return array[index];
    //        }
    //        set
    //        {
    //            if (index < 0 || index >= size)
    //                throw new ArgumentOutOfRangeException(nameof(index));
    //            array[index] = value;
    //        }
    //    }

    //    // Front element
    //    public T Front()
    //    {
    //        if (size == 0) 
    //            throw new InvalidOperationException("Vector is empty.");
    //        return array[0];
    //    }

    //    // Back element
    //    public T Back()
    //    {
    //        if (size == 0) 
    //            throw new InvalidOperationException("Vector is empty.");
    //        return array[size - 1];
    //    }

    //    // Clear the vector
    //    public void Clear()
    //    {
    //        for (int i = 0; i < size; i++)
    //        {
    //            array[i] = default(T); // Clear for GC
    //        }
    //        size = 0;
    //    }

    //    // Insert element at specified position
    //    public void Insert(int index, T item)
    //    {
    //        if (index < 0 || index > size)
    //            throw new ArgumentOutOfRangeException(nameof(index));

    //        EnsureCapacity(size + 1);
    //        Array.Copy(array, index, array, index + 1, size - index);
    //        array[index] = item;
    //        size++;
    //    }

    //    // Remove element at specified position
    //    public void Erase(int index)
    //    {
    //        if (index < 0 || index >= size)
    //            throw new ArgumentOutOfRangeException(nameof(index));

    //        Array.Copy(array, index + 1, array, index, size - index - 1);
    //        array[--size] = default(T); // Clear for GC
    //    }

    //    // Find the index of an element
    //    public int IndexOf(T item)
    //    {
    //        for (int i = 0; i < size; i++)
    //        {
    //            if (EqualityComparer<T>.Default.Equals(array[i], item))
    //                return i;
    //        }
    //        return -1;
    //    }

    //    // Check if the vector contains an element
    //    public bool Contains(T item)
    //    {
    //        return IndexOf(item) != -1;
    //    }

    //    // Ensure the internal array has enough capacity
    //    private void EnsureCapacity(int minCapacity)
    //    {
    //        if (minCapacity > array.Length)
    //        {
    //            int newCapacity = array.Length * 2;
    //            if (newCapacity < minCapacity)
    //                newCapacity = minCapacity;
    //            Array.Resize(ref array, newCapacity);
    //        }
    //    }

    //    // Enumerator to allow foreach iteration
    //    public IEnumerator<T> GetEnumerator()
    //    {
    //        for (int i = 0; i < size; i++)
    //        {
    //            yield return array[i];
    //        }
    //    }

    //    IEnumerator IEnumerable.GetEnumerator()
    //    {
    //        return GetEnumerator();
    //    }
    //}

    #region QVector old
    //public class QVector<T> : IEnumerable<T>
    //{
    //    private List<T> _items;

    //    // Constructor to initialize with a specific size
    //    public QVector(int size = 0)
    //    {
    //        _items = new List<T>(size);
    //    }

    //    // Access element at index
    //    public T this[int index]
    //    {
    //        get => _items[index];
    //        set => _items[index] = value;
    //    }

    //    // Number of elements
    //    public int Count => _items.Count;

    //    // Add new element
    //    public void Add(T item)
    //    {
    //        _items.Add(item);
    //    }

    //    public void AddRange(IEnumerable<T> items)
    //    {
    //        _items.AddRange(items);
    //    }

    //    // Remove an element
    //    public bool Remove(T item)
    //    {
    //        return _items.Remove(item);
    //    }

    //    // Insert an element at a specific index
    //    public void Insert(int index, T item)
    //    {
    //        _items.Insert(index, item);
    //    }

    //    // Clear the list
    //    public void Clear()
    //    {
    //        _items.Clear();
    //    }

    //    // Swap two elements by index
    //    public void Swap(int index1, int index2)
    //    {
    //        if (index1 >= 0 && index2 >= 0 && index1 < _items.Count && index2 < _items.Count)
    //        {
    //            T temp = _items[index1];
    //            _items[index1] = _items[index2];
    //            _items[index2] = temp;
    //        }
    //    }

    //    // Enumerator implementation to support foreach loops
    //    public IEnumerator<T> GetEnumerator()
    //    {
    //        return _items.GetEnumerator();
    //    }

    //    IEnumerator IEnumerable.GetEnumerator()
    //    {
    //        return GetEnumerator();
    //    }
    //}

    #endregion

    public class QVector<T> : IEnumerable<T> where T : new()
    {
        private T[] _array;
        private int _size;
        private int _capacity;

        public QVector()
        {
            _capacity = 4;
            _array = new T[_capacity];
            _size = 0;
        }

        public QVector(int capacity)
        {
            _capacity = capacity;
            _array = new T[_capacity];
            _size = 0;
        }

        // Copy constructor
        public QVector(QVector<T> other)
        {
            _capacity = other._capacity;
            _size = other._size;
            _array = new T[_capacity];
            Array.Copy(other._array, _array, _size);
        }

        // Return the number of elements
        public int Size() => _size;

        // Check if the vector is empty
        public bool Empty() => _size == 0;

        // Get the element at the front
        public T Front() => _array[0];

        // Get the element at the back
        public T Back() => _array[_size - 1];

        // Access an element by index
        public T this[int index]
        {
            get
            {
                if (index >= _size || index < 0)
                    throw new ArgumentOutOfRangeException();
                return _array[index];
            }
            set
            {
                if (index >= _size || index < 0)
                    throw new ArgumentOutOfRangeException();
                _array[index] = value;
            }
        }

        // Add an element at the end
        public void PushBack(T value)
        {
            if (_size == _capacity)
            {
                Resize(_capacity * 2);  // Double the capacity when the array is full
            }
            _array[_size] = value;
            _size++;
        }

        // Remove the last element
        public void PopBack()
        {
            if (_size > 0)
            {
                _size--;
                _array[_size] = default(T);  // Optional: Clear the removed element
            }
        }

        // Resize the vector
        public void Resize(int newSize, T value = default(T))
        {
            if (newSize > _capacity)
            {
                ResizeCapacity(newSize);
            }

            for (int i = _size; i < newSize; i++)
            {
                _array[i] = value;
            }
            _size = newSize;
        }

        private void ResizeCapacity(int newCapacity)
        {
            T[] newArray = new T[newCapacity];
            Array.Copy(_array, newArray, _size);
            _array = newArray;
            _capacity = newCapacity;
        }

        public void AddRange(IEnumerable<T> collection)
        {
            if (collection == null)
                throw new ArgumentNullException(nameof(collection));

            // Calculate the total number of elements to be added
            int collectionCount = 0;
            foreach (var item in collection)
            {
                collectionCount++;
            }

            // Ensure capacity for the new elements
            if (_size + collectionCount > _capacity)
            {
                ResizeCapacity(_size + collectionCount);
            }

            // Add elements to the array
            foreach (var item in collection)
            {
                _array[_size] = item;
                _size++;
            }
        }

        public void Qclear()
        {
            // Clear all elements
            Array.Clear(_array, 0, _size);
            _size = 0; // Reset size, but keep the allocated capacity
        }

        // Clear the vector
        public void Clear()
        {
            _array = new T[_capacity];
            _size = 0;
        }

        // Get an enumerator to support IEnumerable<T>
        public IEnumerator<T> GetEnumerator()
        {
            for (int i = 0; i < _size; i++)
            {
                yield return _array[i];
            }
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        // Insert an element at a specific index
        public void Insert(int index, T value)
        {
            if (index < 0 || index > _size)
                throw new ArgumentOutOfRangeException();

            if (_size == _capacity)
            {
                Resize(_capacity * 2);  // Double the capacity when the array is full
            }

            Array.Copy(_array, index, _array, index + 1, _size - index);
            _array[index] = value;
            _size++;
        }

        // Remove an element at a specific index
        public void Erase(int index)
        {
            if (index < 0 || index >= _size)
                throw new ArgumentOutOfRangeException();

            Array.Copy(_array, index + 1, _array, index, _size - index - 1);
            _size--;
            _array[_size] = default(T);  // Optional: Clear the removed element
        }

        // Check if the vector contains the value
        public bool Has(T value)
        {
            for (int i = 0; i < _size; i++)
            {
                if (EqualityComparer<T>.Default.Equals(_array[i], value))
                    return true;
            }
            return false;
        }

        // Add a unique element
        public bool AddUnique(T value)
        {
            if (!Has(value))
            {
                PushBack(value);
                return true;
            }
            return false;
        }

        // Swap contents with another QVector
        public void Swap(QVector<T> other)
        {
            T[] tempArray = _array;
            int tempSize = _size;
            int tempCapacity = _capacity;

            _array = other._array;
            _size = other._size;
            _capacity = other._capacity;

            other._array = tempArray;
            other._size = tempSize;
            other._capacity = tempCapacity;
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
