#pragma once
#include <fltKernel.h>

/// <summary>
/// author :oxygen
/// 这个是线程安全的  必须先初始化
/// </summary>




namespace kstd {
#define POOL_TAG 'klst'
		enum class InsertType {
			head,
			tail
		};

		template<typename T>
		class Klist {
		private:
			class iterator {
			public:
				iterator(T* ptr,void* listHead) :__node(ptr), __listhead(listHead){}
				T& operator*() const { return *__node; }
				T* operator->() const { return __node; }
				iterator& operator++() {
					
					if (__node != nullptr) {

						auto tmp = __node->link.Flink;
						if (tmp == __listhead) {
							__node = nullptr;
						}
						else {
							__node = CONTAINING_RECORD(tmp, T, link);
						}
					}
			
					return *this;
				}
				bool operator==(const iterator& other)const { return other.__node == this->__node; }
				bool operator!=(const iterator& other)const { return other.__node != this->__node; }
			private:
				T* __node;
				void* __listhead;
			};
		public:
			void init();
			template<typename DestoryFunc>
			void destory(DestoryFunc func=nullptr);
			bool insert(const T target,InsertType type);

			template<typename CompareFunc>
			T* find(const T target,CompareFunc func);

			template<typename CompareFunc>
			T remove(const T target, CompareFunc func);

			ULONG size() const { return __size; }
			iterator begin();
			iterator end();
		private:
			LIST_ENTRY __listHead;
			KSPIN_LOCK __spinLock;
			ULONG __size;
			bool __inited;
		private:
#pragma warning(disable : 4996)
			T* _alloc()const { return (T*)ExAllocatePoolWithTag(NonPagedPool, sizeof(T), POOL_TAG); };
#pragma warning(default : 4996)
			void _free(T* buf) const { ExFreePool(buf); };
		};


		template<typename T>
		inline void Klist<T>::init()
		{
			__inited = true;
			__size = 0;
			InitializeListHead(&__listHead);
			KeInitializeSpinLock(&__spinLock);
		}


		template<typename T>
		inline bool Klist<T>::insert(const T target, InsertType type)
		{
			auto ret = true;
			auto irql = KIRQL{};
			do {
				auto node = _alloc();
				if (node == nullptr) {
					ret = false;
					break;
				}
				*node = target;
				KeAcquireSpinLock(&__spinLock,&irql);
				switch (type)
				{
				case kstd::InsertType::head:
					InsertHeadList(&this->__listHead, &node->link);
					break;
				case kstd::InsertType::tail:
					InsertTailList(&this->__listHead, &node->link);
					break;
				default:
					ret = false;
					break;

				}
				KeReleaseSpinLock(&__spinLock, irql);
			} while (false);
			if (ret) __size++;

			return ret;
		}


		template<typename T>
		inline typename Klist<T>::iterator Klist<T>::begin()
		{
			auto entry = CONTAINING_RECORD(&__listHead.Flink, T, link);

			return iterator(entry,(void*)&__listHead);
		}

		template<typename T>
		inline typename Klist<T>::iterator Klist<T>::end()
		{
			return iterator(nullptr,(void*)&__listHead);
		}

		template<typename T>
		template<typename DestoryFunc>
		inline void Klist<T>::destory(DestoryFunc func)
		{
			auto irql = KIRQL{};

			KeAcquireSpinLock(&__spinLock, &irql);
			while (!IsListEmpty(&__listHead)) {

				auto head = RemoveHeadList(&__listHead);
				auto entry = CONTAINING_RECORD(head, T, link);
				if (func != nullptr) {
					//用户自定义清楚这个节点
					func(entry);
				}
				else {
					_free(entry);
				}
				
			}
			KeReleaseSpinLock(&__spinLock, irql);
		}

		template<typename T>
		template<typename CompareFunc>
		inline T* Klist<T>::find(const T compare, CompareFunc func)
		{
			T* ret=nullptr;
			auto irql = KIRQL{};

			KeAcquireSpinLock(&__spinLock, &irql);
			for (auto i=__listHead.Flink;i!=&__listHead;i=i->Flink) {
				auto entry = CONTAINING_RECORD(i, T, link/*必须具有这个字段 而且还得是LIST_ENTRY*/);
				if (func(compare,*entry)==true) {
					//find
					ret = entry;
					break;
				}

			}
			KeReleaseSpinLock(&__spinLock, irql);
			//not find
			return ret;
		}

		template<typename T>
		template<typename CompareFunc>
		inline T Klist<T>::remove(const T target, CompareFunc func)
		{
			auto ret = T{};

			auto f = find(target, func);
			RemoveEntryList(&f->link);
			if (f != nullptr) {
				ret = *f;
				_free(f);
				__size--;
			}

			return ret;
		}

}
/// <summary>
/// author :oxygen
/// </summary>