// test_ob.c : test cases related to object maanger objects
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "test_ob.h"



VOID Test_ObMap_Insert(POB_MAP pm, DWORD c)
{
    DWORD i;
    for(i = 1; i < c; i++) {
        ObMap_Push(pm, i, (PVOID)(i | 0xffffffff'00000000));
    }
}

VOID Test_ObMap()
{
    /*
    QWORD qw1, qw2;
    DWORD i;
    POB_MAP pm = NULL;
    pm = ObMap_New(OB_MAP_FLAGS_NOKEY);
    Test_ObMap_Insert(pm, 0x001f0000);
    qw1 = ObMap_Peek(pm);
    qw2 = ObMap_PeekKey(pm);
    qw1 = ObMap_Pop(pm);
    qw1 = ObMap_Peek(pm);
    qw2 = ObMap_PeekKey(pm);
    qw1 = ObMap_Pop(pm);
    qw1 = ObMap_Peek(pm);
    qw2 = ObMap_PeekKey(pm);
    qw1 = ObMap_GetByKey(pm, 0x200);
    qw1 = ObMap_PeekKey(pm);
    qw1 = ObMap_ExistsKey(pm, 0x200);
    Ob_DECREF_NULL(&pm);

    for(i = 0; i < 10; i++) {
        pm = ObMap_New(0);
        Test_ObMap_Insert(pm, 0x007f0000);
        ObMap_Clear(pm);
        Test_ObMap_Insert(pm, 0x00020000);
        Ob_DECREF_NULL(&pm);
    }

    DWORD y = 0;
    */
}
