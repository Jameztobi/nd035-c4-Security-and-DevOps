package com.example.demo.controllerTest;

import com.example.demo.TestUtils;
import com.example.demo.controllers.ItemController;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.repositories.ItemRepository;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ItemControllerTest {

    private ItemController itemController;
    private ItemRepository itemRepository = mock(ItemRepository.class);

    @Before
    public void setUp(){
        itemController = new ItemController();
        TestUtils.InjectObjects(itemController, "itemRepository", itemRepository);
    }

    @Test
    public void getItem(){
        when(itemRepository.findAll()).thenReturn(myListOfItems());
        ResponseEntity<List<Item>> responseEntity
                = itemController.getItems();

        List<Item> itemList = responseEntity.getBody();

        itemList.forEach(item -> {
            Assert.assertEquals(true,myListOfItems().contains(item));
        });
    }

    @Test
    public void getItemById(){
        Item item = myListOfItems().get(0);
        when(itemRepository.findById(item.getId())).thenReturn(Optional.of(myListOfItems().get(0)));

        ResponseEntity<Item> responseEntity = itemController.getItemById(item.getId());
        Item returnedItem = responseEntity.getBody();
        assertThat(returnedItem).isEqualTo(item);
    }

    @Test
    public void getItemsByName(){
        Item item = myListOfItems().get(0);
        List myList = new ArrayList<Item>();
        myList.add(item);
        when(itemRepository.findByName(item.getName())).thenReturn(myList);

        ResponseEntity<List<Item>> responseEntity = itemController.getItemsByName(item.getName());
        Item returnedItem = responseEntity.getBody().get(0);
        assertThat(returnedItem).isEqualTo(item);


    }



    public List<Item> myListOfItems(){
        Item item = new Item();
        item.setId(1L);
        item.setPrice(new BigDecimal(5));
        item.setName("Spoon");

        Item item1 = new Item();
        item1.setId(2L);
        item1.setName("Knife");
        item1.setPrice(new BigDecimal(5));
        List myList = new ArrayList<Item>();
        myList.add(item);
        myList.add(item1);
        return myList;
    }

}
