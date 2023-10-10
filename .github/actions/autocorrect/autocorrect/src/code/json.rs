// autocorrect: false
use super::*;
use autocorrect_derive::GrammarParser;
use pest::Parser as P;
use pest_derive::Parser;

#[derive(GrammarParser, Parser)]
#[grammar = "../grammar/json.pest"]
struct JSONParser;

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;
    use pretty_assertions::assert_eq;

    #[test]
    fn it_format_json() {
        let example = indoc! {r###"
        {
          "name": "你好hello世界 \"World\"",
          "displayName": "JSON格式测试",
          "publisher": "huacnlee",
          "meta": {
            // 第1行注释
            "title": "第1个meta", 
            /** 
             * 第2行注释
             * 第3行注释
             */
            "description" : "第2个meta", 
            "测试key不格式化": 
                  "Value要格式化",
          },
          "array": [
            "hello你好",
            "你好hello",
          ],
        }
        "###};

        let expect = indoc! {r###"
        {
          "name": "你好 hello 世界 \"World\"",
          "displayName": "JSON 格式测试",
          "publisher": "huacnlee",
          "meta": {
            // 第 1 行注释
            "title": "第 1 个 meta", 
            /** 
             * 第 2 行注释
             * 第 3 行注释
             */
            "description" : "第 2 个 meta", 
            "测试key不格式化": 
                  "Value 要格式化",
          },
          "array": [
            "hello 你好",
            "你好 hello",
          ],
        }
        "###};

        assert_eq!(expect, format_for(example, "json").to_string());
    }
}
