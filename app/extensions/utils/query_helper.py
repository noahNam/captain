class RawQueryHelper:
    @staticmethod
    def print_raw_query(query):
        """
            raw query 출력용 로그 작성
            model 대신 query 만 전달되도록 해야 함
                ex) query = session.query(Model)
        """
        print(str(query.statement.compile(compile_kwargs={"literal_binds": True})))
