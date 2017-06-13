// MyDLL.cpp: определяет экспортированные функции для приложения DLL.
//

#include "stdafx.h"
#include <iostream>
#include "MyDLL.h"


int return_sum(int a, int b) {
	return a + b;
}