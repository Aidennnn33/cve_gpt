
class deduplication():
    
    def list_deduplicate(self, result_list, list_item):

        reduplication_list = list({result[{list_item}]: result for result in result_list}.values())

        return reduplication_list
