    var vm = new Vue({
        el: '#table',
        data: {
          listData:[],
          page: 1,//当前页码
          pageSize: 5,//每页条数
          total:0,//总数
          pageData: {
            curPage: 1,
            pageSize: 10,
            total: 0,
            totalPage: 0,
            pageIndex: [],
            itemStart: 0,
            itemEnd: 0
          }
        },
        methods:{
          listItems: function () {//列出需要的数据
            var returnData =getData(this.page,this.pageSize);
            this.listData = returnData['data'];
            this.total=returnData['total'];
            this.setPageList(this.total, this.page, this.pageSize);
          },
          editItem:function ($id) {//编辑操作在这儿哟
            alert('编辑第'+$id+'条数据！');
          },
          deleteItem:function ($id) {//这里可以删除数据
            alert('删除第'+$id+'条数据！');
          },
          setPageList: function (total, page, pageSize) {
          total = parseInt(total);
          var curPage = parseInt(page);
          pageSize = parseInt(pageSize);
          var totalPage = Math.ceil(total / pageSize);
          var itemStart = (curPage - 1) * pageSize + 1;
          if (curPage == totalPage) {
            itemEnd = total;
          } else {
            itemEnd = curPage * pageSize;
          }
          var pageIndex = [];
          if (curPage >= 1 && curPage <= totalPage) {
            if (totalPage < 5) {//5页以内
              for (var $i = 1; $i <= totalPage; $i++) {
                pageIndex.push($i);
              }
            } else {//大于5页
              if (curPage == 1) {
                pageIndex = [curPage, curPage + 1, curPage + 2, curPage + 3, curPage + 4];
              } else if (curPage == 2) {
                pageIndex = [curPage - 1, curPage, curPage + 1, curPage + 2, curPage + 3];
              } else if (curPage == totalPage - 1) {
                pageIndex = [curPage - 3, curPage - 2, curPage - 1, curPage, totalPage];
              } else if (curPage == totalPage) {
                pageIndex = [curPage - 4, curPage - 3, curPage - 2, curPage - 1, curPage];
              } else {
                pageIndex = [curPage - 2, curPage - 1, curPage, curPage + 1, curPage + 2];
              }
            }
          }
   
          this.pageData.curPage = curPage;
          this.pageData.pageSize = pageSize;
          this.pageData.total = total;
          this.pageData.totalPage = totalPage;
          this.pageData.pageIndex = pageIndex;
          this.pageData.itemStart = itemStart;
          this.pageData.itemEnd = itemEnd;
        },
        changeCurPage: function (page, pageSize) {//换页
          this.page = page;
          this.pageSize = pageSize;
          this.listItems();
        },
        goPage: function (pageSize, totalPage) {//跳转页
          var pageIndex = this.$refs.goPage.value;
          if (pageIndex <= 0) {
            pageIndex = 1;
            this.$refs.goPage.value = 1;
          } else if (pageIndex >= totalPage) {
            pageIndex = totalPage;
            this.$refs.goPage.value = totalPage;
          }
          this.changeCurPage(pageIndex, pageSize);
        }
        }
      });